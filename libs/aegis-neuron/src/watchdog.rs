use notify::{Watcher, RecursiveMode, Result, EventKind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::thread;

pub struct Watchdog {
    path: PathBuf,
}

impl Watchdog {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn watch<F>(&self, callback: F) -> Result<()> 
    where F: Fn(PathBuf) + Send + 'static {
        let path = self.path.clone();
        
        thread::spawn(move || {
            let (tx, rx) = channel();
            let mut watcher = notify::recommended_watcher(tx).unwrap();
            
            if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
                eprintln!("[Neuron] Watchdog failed to start: {}", e);
                return;
            }
            
            println!("[Neuron] Watchdog active on: {:?}", path);

            for res in rx {
                match res {
                    Ok(event) => {
                        if let EventKind::Create(_) = event.kind {
                            for path in event.paths {
                                callback(path);
                            }
                        }
                    },
                    Err(e) => eprintln!("[Neuron] Watch error: {:?}", e),
                }
            }
        });
        
        Ok(())
    }
}
