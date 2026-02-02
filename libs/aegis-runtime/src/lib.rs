pub mod interface;
pub mod plugin_engine;

use wasmtime_wasi::WasiCtx;

pub use plugin_engine::{PluginEngine, PluginInstance};

pub struct WasmContext {
    pub wasi: WasiCtx,
    pub plugin_name: String,
}
