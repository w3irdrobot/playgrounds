use wit::*;

struct Function;

impl Guest for Function {
    fn run() {
        match get_entropy(32) {
            Ok(ent) => {
                log(&format!("the given entropy was {}", hex::encode(ent)));
            }
            Err(error) => log(&format!("error getting entropy: {}", error)),
        }
    }

    fn name() -> String {
        "print".to_string()
    }
}

export!(Function);
