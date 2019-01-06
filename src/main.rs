use std::env;
use std::fs::File;
use std::io;
use std::str;
use nom::*;
use nom::Context::{
    Code,
};
use nom::Err::*;
use nom::types::*;

#[derive(Debug, PartialEq)]
struct JailConfParam {
    name:  String,
    value: String,
}

#[derive(Debug, PartialEq)]
struct JailConf {
    name:   String,
    params: Vec<JailConfParam>,
}

// Parse the jail name
named!(
    parse_name<&[u8], &[u8]>,
    take_until_either!(" {")
);

// Parse a param name
named!(
    parse_param_name<&[u8], &[u8]>,
    take_until_either!(" +=")
);

// Parse a param value
named!(
    parse_param_value<&[u8], &[u8]>,
    take_until!(";")
);

named!(
    parse_param<&[u8], (&[u8], &[u8])>,
    ws!(
        do_parse!(
            pname: take_until_either!(" +=") >>
            opt_res!(char!('+')) >>
            opt_res!(char!('=')) >>
            pval: take_until!(";") >>
            char!(';') >>
            (pname, pval)
        )
    )
);

named!(
    parse_params<&[u8], Vec<(&[u8], &[u8])>>,
    many_till!(parse_param, tag!("}"))
);

named!(
    parser<&[u8], (&[u8], Vec<(&[u8], &[u8])>)>,
    ws!(
        do_parse!(
            name: parse_name >>
            char!('{') >>
            params: parse_params >>
            char!('}') >>
            eof!() >>
            (name, params)
        )
    )
);

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

    let mut buffer = vec![]; //String::new();
    input.read_to_end(&mut buffer).unwrap();

    let result = parser(&buffer[..]);
    let result = match result {
        Ok(r)  => r,
        Err(e) => {
            match e {
                Error(Code(i, k)) => {
                    eprintln!("I: {}", str::from_utf8(i).unwrap());
                    eprintln!("K: {:?}", k);
                },
                Failure(f) => {
                    eprintln!("{:?}", f);
                }
                Incomplete(n) => {
                    eprintln!("{:?}", e);
                },
            }
            std::process::exit(1);
        },
    };
    let (a, b) = result;
    let stra = str::from_utf8(a);

    let (c, d) = b;
    //let strb = b; //str::from_utf8(b);
    let strc = str::from_utf8(c);

    println!("A: {:?}", stra);
    println!("B: {:?}", strc);
    println!("{:?}", d);
}
