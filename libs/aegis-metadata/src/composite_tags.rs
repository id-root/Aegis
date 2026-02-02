use std::collections::HashMap;

pub struct CompositeTagEngine;

impl CompositeTagEngine {
    pub fn calculate_virtual_tags(tags: &HashMap<String, String>) -> HashMap<String, String> {
        let mut virtual_tags = HashMap::new();

        if let (Some(focal_len), Some(sensor_width)) = (tags.get("FocalLength"), tags.get("SensorWidth")) {
            if let (Ok(fl), Ok(sw)) = (focal_len.parse::<f64>(), sensor_width.parse::<f64>()) {
                let fov = 2.0 * (sw / (2.0 * fl)).atan();
                let fov_deg = fov.to_degrees();
                virtual_tags.insert("Composite:FieldOfView".to_string(), format!("{:.2} deg", fov_deg));
            }
        }

        if let (Some(shutter_speed), Some(aperture)) = (tags.get("ShutterSpeed"), tags.get("Aperture")) {
             // EV = log2(N^2 / t)
             // N = aperture, t = shutter speed
             if let (Ok(ss), Ok(ap)) = (shutter_speed.parse::<f64>(), aperture.parse::<f64>()) {
                 let ev = (ap.powi(2) / ss).log2();
                 virtual_tags.insert("Composite:EV".to_string(), format!("{:.2}", ev));
             }
        }

        virtual_tags
    }
}
