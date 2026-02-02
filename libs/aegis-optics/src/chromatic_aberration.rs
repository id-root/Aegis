use image::{DynamicImage, RgbImage};
use rayon::prelude::*;

pub struct LcaDetectionResult {
    pub vector_field: Vec<((u32, u32), (f64, f64))>,
    pub is_suspicious: bool,
}

pub fn detect_lca(image: &DynamicImage) -> LcaDetectionResult {
    let width = image.width();
    let height = image.height();
    let rgb_image = image.to_rgb8();

    // Analyze in 32x32 blocks
    let block_size = 32;
    let grid_x = width / block_size;
    let grid_y = height / block_size;

    let center_x = width as f64 / 2.0;
    let center_y = height as f64 / 2.0;

    // Use Rayon for parallel processing of blocks
    let img_ref = &rgb_image;
    let results: Vec<((u32, u32), (f64, f64))> = (0..grid_y).into_par_iter().flat_map(move |gy| {
        (0..grid_x).into_par_iter().map(move |gx| {
            let x = gx * block_size;
            let y = gy * block_size;

            let (shift_x, shift_y) = calculate_block_shift(img_ref, x, y, block_size);
            ((x + block_size / 2, y + block_size / 2), (shift_x, shift_y))
        })
    }).collect();

    let mut suspicion_score = 0;
    
    // Check for radial integrity
    for &((px, py), (vx, vy)) in &results {
        // Vector from center to block center
        let dx = px as f64 - center_x;
        let dy = py as f64 - center_y;
        
        // Normalized direction from center
        let len = (dx * dx + dy * dy).sqrt();
        if len < 1.0 { continue; }
        let dir_x = dx / len;
        let dir_y = dy / len;

        // Normalized shift vector
        let shift_len = (vx * vx + vy * vy).sqrt();
        if shift_len < 0.1 { continue; } // Ignore negligible shifts
        let shift_dir_x = vx / shift_len;
        let shift_dir_y = vy / shift_len;

        // Dot product to check alignment (should be close to 1.0 or -1.0 for radial)
        let alignment = (dir_x * shift_dir_x + dir_y * shift_dir_y).abs();
        
        // If alignment is low, it means the aberration isn't radial -> suspicious
        if alignment < 0.8 {
            suspicion_score += 1;
        }
    }

    let is_suspicious = suspicion_score > (results.len() / 10); // Threshold: >10% anomalous blocks

    LcaDetectionResult {
        vector_field: results,
        is_suspicious,
    }
}

fn calculate_block_shift(image: &RgbImage, start_x: u32, start_y: u32, size: u32) -> (f64, f64) {
    // Simplified cross-correlation logic to detect shift between Red/Blue and Green channels
    // In a real implementation, this would do a localized cross-correlation search.
    // Here we act as a placeholder for the physics logic described.
    
    // We'll calculate centroids of intensity for R, G, B in the block and see relative shifts.
    let mut sum_r_x = 0.0;
    let mut sum_r_y = 0.0;
    let mut sum_r_w = 0.0;

    let mut sum_g_x = 0.0;
    let mut sum_g_y = 0.0;
    let mut sum_g_w = 0.0;
    
    let mut _sum_b_x = 0.0;
    let mut _sum_b_y = 0.0;
    let mut sum_b_w = 0.0;

    for y in 0..size {
        for x in 0..size {
            if start_x + x >= image.width() || start_y + y >= image.height() { continue; }
            
            let pixel = image.get_pixel(start_x + x, start_y + y);
            let r = pixel[0] as f64;
            let g = pixel[1] as f64;
            let b = pixel[2] as f64;

            sum_r_x += x as f64 * r;
            sum_r_y += y as f64 * r;
            sum_r_w += r;

            sum_g_x += x as f64 * g;
            sum_g_y += y as f64 * g;
            sum_g_w += g;
            
            _sum_b_x += x as f64 * b;
            _sum_b_y += y as f64 * b;
            sum_b_w += b;
        }
    }

    if sum_r_w == 0.0 || sum_g_w == 0.0 || sum_b_w == 0.0 {
        return (0.0, 0.0);
    }

    let c_r_x = sum_r_x / sum_r_w;
    let c_r_y = sum_r_y / sum_r_w;

    let c_g_x = sum_g_x / sum_g_w;
    let c_g_y = sum_g_y / sum_g_w;

    // Relative shift of Red channel from Green (reference)
    let shift_x = c_r_x - c_g_x;
    let shift_y = c_r_y - c_g_y;

    (shift_x, shift_y)
}
