use wasmtime::Caller;
use crate::WasmContext;

// Host functions accessible to WASM plugins
pub fn host_log(mut caller: Caller<'_, WasmContext>, ptr: i32, len: i32) {
    let mem = match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => m,
        _ => return,
    };
    
    let ctx = caller.data();
    // Safety: In a real implementation we must check bounds diligently.
    // For prototype, we assume the WASM module is behaving within reason or we catch traps.
    
    let buffer = match mem.data(&caller).get(ptr as usize..(ptr + len) as usize) {
        Some(b) => b,
        None => return, // Invalid memory access
    };
    
    if let Ok(msg) = std::str::from_utf8(buffer) {
        println!("[PLUGIN {}] {}", ctx.plugin_name, msg);
    }
}
