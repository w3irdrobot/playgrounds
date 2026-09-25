use rand::TryRng;
use wasmtime::component::*;
use wasmtime::{Engine, Store};
use wit::server::*;

#[derive(Debug, Default)]
struct ComponentState {
    name: Option<String>,
}

impl RuntimeImports for ComponentState {
    fn get_entropy(&mut self, length: u32) -> Result<Vec<u8>, Error> {
        if length > 1024 || length == 0 {
            Err(Error::LengthOutOfBounds)
        } else {
            let mut data = vec![0; length as usize];
            rand::rng()
                .try_fill_bytes(&mut data)
                .map_err(|_| Error::EntropyGenerationFailed)?;
            Ok(data)
        }
    }

    fn log(&mut self, message: String) {
        let name = self.name.as_deref().unwrap_or("default program name");
        println!("[INFO]{}: {}", name, message);
    }
}

fn main() {
    let mut args = std::env::args();
    if args.len() <= 1 {
        eprintln!("You need to pass a WASM binary to run.");
        std::process::exit(1);
    }

    let bin = args.nth(1).expect("a WASM binary");

    let engine = Engine::default();
    let component = Component::from_file(&engine, bin).unwrap();

    let mut linker = Linker::new(&engine);
    Runtime::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state).unwrap();

    let mut store: Store<ComponentState> = Store::new(&engine, ComponentState::default());
    let instance = Runtime::instantiate(&mut store, &component, &linker).unwrap();

    let name = instance.call_name(&mut store).unwrap();
    store.data_mut().name = Some(name);
    instance.call_run(&mut store).unwrap();
}
