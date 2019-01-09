use std::env;
use std::fs::File;
use std::io;
use std::str;
use nom::*;
use nom::Context::{
    Code,
};
use nom::Err::*;

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

// Parse a valueless boolean in the style of:
//   - allow.mount;
//   - persist;
//   - etc;
//
// Other types of value will error.
named!(
    parse_bool_param_no_value<&[u8], &[u8]>,
    do_parse!(
        res: take_until_either!(" +=;\n") >> // Consume until an interesting char
             not!(is_a!(" +=\n"))         >> // Ensure it's not a banned char
             char!(';')                   >> // Consume terminating ;
        (res)
    )
);

// Parse a parameter with an associated value.
//   - allow.mount = true;
//   - allow.sysvipc="1";
//   - ip4.addr = "127.0.1.1";
//   - ip4.addr += "127.0.1.2";
//
// Other types of value will error.
// This will choke if a value contained a quoted double quote, we should be
// able to use escaped!() to help with this.
named!(
    parse_param_with_value<&[u8], (&[u8], &[u8])>,
    do_parse!(
        param: take_until_either!(" +=;\n") >>
               not!(is_a!(";\n"))           >> // We don't want end of line yet
               space0                       >> // Optional spaces
               opt_res!(char!('+'))         >> // Optional +
               char!('=')                   >> // = is mandatory
               space0                       >> // Optional spaces
        value: delimited!(
                   opt_res!(tag!("\"")),        // Possible opening quote
                   take_until_either!("\";\n"), // value
                   opt_res!(tag!("\""))         // Possible closing quote
               )                            >>
               not!(is_a!("\n"))            >> // Ensure no new line yet
               char!(';')                   >> // Terminating ;
        (param, value)
    )
);

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
    many0!(parse_param)
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
                Incomplete(_n) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Valueless boolean params
    #[test]
    fn test_parse_bool_param_no_value() {
        let item = "allow.mount;".as_bytes();
        let res = parse_bool_param_no_value(item);
        let ok = Ok(("".as_bytes(), "allow.mount".as_bytes()));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_trailing_newline() {
        let item = "allow.mount;\n".as_bytes();
        let res = parse_bool_param_no_value(item);
        let ok = Ok(("\n".as_bytes(), "allow.mount".as_bytes()));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_with_value_error() {
        let item = "allow.mount = true;".as_bytes();
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    #[test]
    fn test_parse_bool_param_multiline_a() {
        let item = "allow.mount;\npersist;".as_bytes();
        let res = parse_bool_param_no_value(item);
        let ok = Ok(("\npersist;".as_bytes(), "allow.mount".as_bytes()));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_multiline_error() {
        let item = "allow.mount\n;".as_bytes();
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    // Parameters with values
    #[test]
    fn test_parse_param_with_value() {
        let item = "allow.mount = true;".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "".as_bytes(),
                ("allow.mount".as_bytes(), "true".as_bytes())
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_value_utf8() {
        let item = "allow.mount = \"😁\";".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "".as_bytes(),
                ("allow.mount".as_bytes(), "😁".as_bytes())
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_value_trailing_newline() {
        let item = "allow.mount = true;\n".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "\n".as_bytes(),
                ("allow.mount".as_bytes(), "true".as_bytes())
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value() {
        let item = "allow.mount = \"true\";".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "".as_bytes(),
                ("allow.mount".as_bytes(), "true".as_bytes())
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_trailing_newline() {
        let item = "allow.mount = \"true\";\n".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "\n".as_bytes(),
                ("allow.mount".as_bytes(), "true".as_bytes())
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_no_spaces() {
        let item = "allow.mount=\"true\";".as_bytes();
        let res = parse_param_with_value(item);
        let ok = Ok((
                "".as_bytes(),
                ("allow.mount".as_bytes(), "true".as_bytes())
                ));

        assert_eq!(res, ok);
    }
}
