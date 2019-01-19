use std::env;
use std::fs::File;
use std::io;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut input: Box<io::Read> = if args.len() > 1 {
        let filename = &args[1];
        let fh = File::open(filename).unwrap();
        Box::new(fh)
    }
    else {
        let stdin = io::stdin();
        Box::new(stdin)
    };

    let mut buffer = String::new();
    input.read_to_string(&mut buffer).unwrap();

    let result = jailconf::parse(&buffer);
    let result = match result {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("{:?}", e);
            std::process::exit(1);
        },
    };
    println!("{:?}", result);
}
