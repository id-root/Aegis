use std::f64;

struct City {
    name: &'static str,
    lat: f64,
    lon: f64,
}

// Micro-database of major capitals
const CITIES: &[City] = &[
    City { name: "New York, USA", lat: 40.7128, lon: -74.0060 },
    City { name: "London, UK", lat: 51.5074, lon: -0.1278 },
    City { name: "Paris, France", lat: 48.8566, lon: 2.3522 },
    City { name: "Tokyo, Japan", lat: 35.6762, lon: 139.6503 },
    City { name: "Berlin, Germany", lat: 52.5200, lon: 13.4050 },
    City { name: "Moscow, Russia", lat: 55.7558, lon: 37.6173 },
    City { name: "Beijing, China", lat: 39.9042, lon: 116.4074 },
    City { name: "Sydney, Australia", lat: -33.8688, lon: 151.2093 },
    City { name: "Rio de Janeiro, Brazil", lat: -22.9068, lon: -43.1729 },
    City { name: "Cairo, Egypt", lat: 30.0444, lon: 31.2357 },
    // Add more as needed...
];

pub fn reverse_geocode(lat: f64, lon: f64) -> Option<String> {
    let mut nearest = None;
    let mut min_dist = f64::MAX;

    for city in CITIES {
        let dist = haversine(lat, lon, city.lat, city.lon);
        if dist < min_dist {
            min_dist = dist;
            nearest = Some(city.name);
        }
    }

    if min_dist < 500.0 { // 500 km radius matching
        Some(nearest?.to_string())
    } else {
        Some(format!("Unknown Region (Nearest: {} at {:.0}km)", nearest?, min_dist))
    }
}

fn haversine(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0; // Earth radius km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}
