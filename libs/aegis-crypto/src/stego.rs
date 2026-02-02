use image::DynamicImage;
use anyhow::{Result, anyhow};

const BLOCK_SIZE: u32 = 8;
const COMPLEXITY_THRESHOLD: u32 = 40; 

pub fn embed(image: DynamicImage, payload: &[u8]) -> Result<DynamicImage> {
    let mut img = image.to_rgba8();
    let (width, height) = img.dimensions();
    
    // Payload to bits
    let mut payload_bits: Vec<bool> = Vec::new();
    let len = payload.len() as u32;
    // Embed length (32 bits)
    for i in 0..32 {
        payload_bits.push(((len >> (31 - i)) & 1) == 1);
    }
    // Embed data
    for &byte in payload {
        for i in 0..8 {
            payload_bits.push(((byte >> (7 - i)) & 1) == 1);
        }
    }

    let mut bit_idx = 0;
    
    // Iterate 8x8 blocks
    for y in (0..height).step_by(BLOCK_SIZE as usize) {
        for x in (0..width).step_by(BLOCK_SIZE as usize) {
            if x + BLOCK_SIZE > width || y + BLOCK_SIZE > height { continue; }

            for channel in 0..3 {
                for plane in 0..8 {
                    if bit_idx >= payload_bits.len() {
                        return Ok(DynamicImage::ImageRgba8(img));
                    }

                    // Extract original bit plane
                    let mut plane_bits = [[false; 8]; 8];
                    for by in 0..8 {
                        for bx in 0..8 {
                            let pixel = img.get_pixel(x + bx, y + by);
                            let val = pixel[channel as usize];
                            let gray = val ^ (val >> 1);
                            plane_bits[by as usize][bx as usize] = ((gray >> plane) & 1) == 1;
                        }
                    }

                    // Check original complexity
                    let k = calculate_complexity(&plane_bits);
                    
                    if k > COMPLEXITY_THRESHOLD {
                        // We have 64 spots. Reserve (0,0) for conjugation flag.
                        // We can use 63 bits.
                        let mut temp_block = [[false; 8]; 8];
                        
                        // Fill with payload (63 bits)
                        let start_bit_idx = bit_idx;
                        let mut _p_idx = 0;
                        for by in 0..8 {
                            for bx in 0..8 {
                                if bx == 0 && by == 0 { continue; } // Skip flag
                                if bit_idx < payload_bits.len() {
                                    temp_block[by][bx] = payload_bits[bit_idx];
                                    bit_idx += 1;
                                } else {
                                    // Padding with 0
                                    temp_block[by][bx] = false; 
                                }
                                _p_idx += 1;
                            }
                        }

                        // Try Raw (Flag = 0)
                        temp_block[0][0] = false;
                        let k_raw = calculate_complexity(&temp_block);
                        
                        let mut final_block = temp_block;
                        
                        if k_raw <= COMPLEXITY_THRESHOLD {
                            // Conjugate!
                            // Conjugation: XOR with checkerboard (0, 1, 0, 1...)
                            // But we must preserve the Flag bit? No, flag indicates if we applied XOR.
                            // If Flag=1, it means the REST is XORed.
                            // So we set Flag=1, and XOR the rest.
                            
                            final_block[0][0] = true;
                            for by in 0..8 {
                                for bx in 0..8 {
                                    if bx == 0 && by == 0 { continue; }
                                    // Checkerboard pattern: (bx + by) % 2 == 1 -> true?
                                    let pattern = (bx + by) % 2 == 1;
                                    final_block[by][bx] = temp_block[by][bx] ^ pattern;
                                }
                            }
                        }

                        // CRITICAL FIX: Ensure the final block is complex enough to be detected by extractor.
                        // The extractor calculates complexity of the *final* block in the image.
                        // If we embedded data that made the block "simple" (low complexity), the extractor will SKIP it.
                        // But we just consumed payload bits for it! This causes DESYNC.
                        // To fix: If final block is simple, we write it (to consume space) but DO NOT consume payload bits.
                        // effectively "skipping" this block for payload storage.
                        
                        let final_k = calculate_complexity(&final_block);
                        if final_k <= COMPLEXITY_THRESHOLD {
                            // Revert bit_idx to start of this block so we retry these bits in the next block.
                            // We still write 'final_block' to the image (which is now simple) because the extractor will see it
                            // as simple and skip it, seeking the next complex block.
                            // So we just burned this block without embedding valid payload bits.
                            bit_idx = start_bit_idx;
                        }


                        // Write back final_block
                        for by in 0..8 {
                            for bx in 0..8 {
                                let px = x + bx;
                                let py = y + by;
                                let mut pixel = *img.get_pixel(px, py);
                                let val = pixel[channel as usize];
                                let gray = val ^ (val >> 1);
                                
                                let bit = if final_block[by as usize][bx as usize] { 1 } else { 0 };
                                let mask = 1 << plane;
                                let new_gray = (gray & !mask) | (bit << plane);
                                
                                // Inverse Gray
                                let mut mask_gray = new_gray >> 1;
                                let mut new_bin = new_gray;
                                while mask_gray != 0 {
                                    new_bin = new_bin ^ mask_gray;
                                    mask_gray = mask_gray >> 1;
                                }
                                
                                pixel[channel as usize] = new_bin;
                                img.put_pixel(px, py, pixel);
                            }
                        }
                    }
                }
            }
        }
    }
    
    if bit_idx < payload_bits.len() {
        return Err(anyhow!("Image too small to hold payload"));
    }

    Ok(DynamicImage::ImageRgba8(img))
}

pub fn extract(image: DynamicImage) -> Result<Vec<u8>> {
    let img = image.to_rgba8();
    let (width, height) = img.dimensions();
    
    let mut collected_bits: Vec<bool> = Vec::new();
    let mut reading_len = true;
    let mut length = 0u32;
    let mut bits_in_len = 0;
    
    for y in (0..height).step_by(BLOCK_SIZE as usize) {
        for x in (0..width).step_by(BLOCK_SIZE as usize) {
            if x + BLOCK_SIZE > width || y + BLOCK_SIZE > height { continue; }

            for channel in 0..3 {
                for plane in 0..8 {
                    // Extract bit plane
                    let mut plane_bits = [[false; 8]; 8];
                    for by in 0..8 {
                        for bx in 0..8 {
                            let val = img.get_pixel(x + bx, y + by)[channel as usize];
                            let gray = val ^ (val >> 1);
                            plane_bits[by as usize][bx as usize] = ((gray >> plane) & 1) == 1;
                        }
                    }

                    let k = calculate_complexity(&plane_bits);
                    
                    if k > COMPLEXITY_THRESHOLD {
                        // Found a payload block
                        let is_conjugated = plane_bits[0][0];
                        
                        for by in 0..8 {
                            for bx in 0..8 {
                                if bx == 0 && by == 0 { continue; }
                                
                                let mut bit = plane_bits[by][bx];
                                if is_conjugated {
                                    let pattern = (bx + by) % 2 == 1;
                                    bit = bit ^ pattern;
                                }
                                
                                collected_bits.push(bit);
                                
                                if reading_len {
                                    bits_in_len += 1;
                                    if bits_in_len == 32 {
                                        // Reconstruct length
                                        for i in 0..32 {
                                            if collected_bits[i] {
                                                length |= 1 << (31 - i);
                                            }
                                        }
                                        // Sanity check length
                                        if length > 100_000_000 { // 100MB limit
                                             return Err(anyhow!("Invalid payload length: {}", length));
                                        }
                                        
                                        reading_len = false;
                                    }
                                }
                            }
                        }
                        
                        if !reading_len && collected_bits.len() >= (32 + length * 8) as usize {
                            return bits_to_bytes(&collected_bits[32..32+(length * 8) as usize]);
                        }
                    }
                }
            }
        }
    }
    
    Err(anyhow!("Payload not found or incomplete"))
}

fn calculate_complexity(bits: &[[bool; 8]; 8]) -> u32 {
    let mut k = 0;
    for y in 0..8 {
        for x in 0..7 {
            if bits[y][x] != bits[y][x+1] { k += 1; }
        }
    }
    for x in 0..8 {
        for y in 0..7 {
            if bits[y][x] != bits[y+1][x] { k += 1; }
        }
    }
    k
}

fn bits_to_bytes(bits: &[bool]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 { break; }
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b { byte |= 1 << (7 - i); }
        }
        bytes.push(byte);
    }
    Ok(bytes)
}
