use image::{DynamicImage, GrayImage};
use std::collections::HashMap;

#[derive(Debug)]
pub struct CloneMatch {
    pub source: (u32, u32),
    pub target: (u32, u32),
    pub size: u32,
}

/// Detects Copy-Move forgery using block-based hashing.
/// Sliding window of size `block_size` over the image.
/// Hashes content. If collision, potential clone.
/// Note: Sensitive to rotation/scaling (Classic Copy-Move limitation, but effective for naive clones).
pub fn detect_copy_move(img: &DynamicImage, block_size: u32) -> Vec<CloneMatch> {
    let gray = img.to_luma8();
    let (width, height) = gray.dimensions();
    
    let mut map: HashMap<u64, Vec<(u32, u32)>> = HashMap::new();
    let mut matches = Vec::new();
    
    let step = block_size / 2; // Overlapping blocks
    
    // Performance limit: Resize if too huge
    let process_img = if width > 2000 {
        image::imageops::resize(&gray, width/2, height/2, image::imageops::FilterType::Nearest)
    } else {
        gray
    };
    
    let (p_w, p_h) = process_img.dimensions();

    for y in (0..p_h - block_size).step_by(step as usize) {
        for x in (0..p_w - block_size).step_by(step as usize) {
            let hash = compute_block_hash(&process_img, x, y, block_size);
            
            map.entry(hash).or_insert(Vec::new()).push((x, y));
        }
    }
    
    for (_, regions) in map {
        if regions.len() > 1 {
            // Filter adjacent blocks (false positives from smooth regions)
            // We only care if they are far apart.
            for i in 0..regions.len() {
                for j in i+1..regions.len() {
                    let (x1, y1) = regions[i];
                    let (x2, y2) = regions[j];
                    
                    let dist = ((x1 as i32 - x2 as i32).pow(2) + (y1 as i32 - y2 as i32).pow(2)) as f32;
                    let min_dist = (block_size * 4) as f32; // Must be far apart
                    
                    if dist > min_dist.powf(2.0) {
                        matches.push(CloneMatch {
                            source: (x1, y1),
                            target: (x2, y2),
                            size: block_size,
                        });
                        // Limit matches per hash to avoid combinatorial explosion on flat areas
                        if matches.len() > 50 { return matches; }
                    }
                }
            }
        }
    }
    
    matches
}

// Simple perceptual hash for a block
fn compute_block_hash(img: &GrayImage, x: u32, y: u32, size: u32) -> u64 {
    let mut sum: u64 = 0;
    let mut avg = 0;
    
    // 1. Calculate average brightness
    for dy in 0..size {
        for dx in 0..size {
             avg += img.get_pixel(x + dx, y + dy).0[0] as u64;
        }
    }
    avg /= (size * size) as u64;
    
    // 2. Hash bits > avg
    for dy in 0..size {
        for dx in 0..size {
            let val = img.get_pixel(x + dx, y + dy).0[0] as u64;
             if val > avg {
                 sum = (sum << 1) | 1;
             } else {
                 sum = sum << 1;
             }
        }
    }
    sum
}
