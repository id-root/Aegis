#![no_main]
use libfuzzer_sys::fuzz_target;
use aegis_metadata::MakerNoteDecoder;

fuzz_target!(|data: &[u8]| {
    // Fuzz the parsing logic with arbitrary byte streams
    let decoder = MakerNoteDecoder::new();
    
    // We check against all vendors for each input to maximize coverage
    let _ = decoder.decode("Canon", data);
    let _ = decoder.decode("Nikon", data);
    let _ = decoder.decode("Sony", data);
});
