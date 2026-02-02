use anyhow::{Result, Context};
use wasmtime::*;
use wasmtime_wasi::sync::WasiCtxBuilder;
use crate::WasmContext;
use crate::interface;

pub struct PluginEngine {
    engine: Engine,
    linker: Linker<WasmContext>,
}

impl PluginEngine {
    pub fn new() -> Result<Self> {
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        
        // Link WASI default functions
        wasmtime_wasi::add_to_linker(&mut linker, |ctx: &mut WasmContext| &mut ctx.wasi)?;
        
        // Link custom host functions
        linker.func_wrap("env", "host_log", interface::host_log)?;

        Ok(PluginEngine { engine, linker })
    }

    pub fn load_plugin(&self, path: &str, name: &str) -> Result<PluginInstance> {
        let module = Module::from_file(&self.engine, path).context("Failed to load WASM file")?;
        
        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();
            
        let context = WasmContext {
            wasi,
            plugin_name: name.to_string(),
        };
        
        let mut store = Store::new(&self.engine, context);
        let instance = self.linker.instantiate(&mut store, &module).context("Failed to instantiate module")?;
        
        Ok(PluginInstance { store, instance })
    }
}

pub struct PluginInstance {
    store: Store<WasmContext>,
    instance: Instance,
}

impl PluginInstance {
    pub fn run_analyze(&mut self) -> Result<()> {
        // Assume plugins export a "run" function
        let run_func = self.instance.get_typed_func::<(), ()>(&mut self.store, "run")?;
        run_func.call(&mut self.store, ())?;
        Ok(())
    }
}
