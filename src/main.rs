use std::env;
use std::fs::File;
use std::io;
use std::str;
use nom::*;
use nom::Context::{
    Code,
    List,
};
use nom::Err::*;
use nom::types::CompleteStr;

#[derive(Debug, PartialEq)]
struct JailParamBool<'a> {
    name: CompleteStr<'a>,
}

#[derive(Debug, PartialEq)]
struct JailParamValue<'a> {
    name:  CompleteStr<'a>,
    value: CompleteStr<'a>,
}

#[derive(Debug, PartialEq)]
struct JailBlock<'a> {
    name:   CompleteStr<'a>,
    params: Vec<JailConf<'a>>,
}

#[derive(Debug, PartialEq)]
enum JailConf<'a> {
    Block(JailBlock<'a>),
    ParamBool(JailParamBool<'a>),
    ParamValue(JailParamValue<'a>),
}

// Parse a valueless boolean in the style of:
//   - allow.mount;
//   - persist;
//   - etc;
//
// Other types of value will error.
named!(
    parse_bool_param_no_value<CompleteStr, CompleteStr>,
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
    parse_param_with_value<CompleteStr, (CompleteStr, CompleteStr)>,
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


named!(
    parse_input<CompleteStr, Vec<JailConf>>,
    do_parse!(
        // We attempt parsers many times until the input is exhausted.
        config: many0!(
            // Config could be in pretty much any order.
            ws!(alt!(
                // Parse a boolean parameter with no values.
                parse_bool_param_no_value => { |param|
                    JailConf::ParamBool(JailParamBool{
                        name: param,
                    })
                } |
                // Parse a parameter with a value.
                parse_param_with_value => { |(param, value)|
                    JailConf::ParamValue(JailParamValue{
                        name:  param,
                        value: value,
                    })
                }
            ))
        ) >>

        (config)
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

    let mut buffer = String::new();
    input.read_to_string(&mut buffer).unwrap();

    let result = parse_input(CompleteStr(&buffer));
    let result = match result {
        Ok(r)  => r,
        Err(e) => {
            match e {
                Error(Code(i, k)) => {
                    eprintln!("I: {}", i);
                    eprintln!("K: {:?}", k);
                },
                Error(List(l)) => {
                    eprintln!("{:?}", l);
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
    println!("{:?}", a);
    println!("{:?}", b);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valueless boolean params
    #[test]
    fn test_parse_bool_param_no_value() {
        let item = CompleteStr("allow.mount;");
        let res = parse_bool_param_no_value(item);
        let ok = Ok((CompleteStr(""), CompleteStr("allow.mount")));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_trailing_newline() {
        let item = CompleteStr("allow.mount;\n");
        let res = parse_bool_param_no_value(item);
        let ok = Ok((CompleteStr("\n"), CompleteStr("allow.mount")));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_with_value_error() {
        let item = CompleteStr("allow.mount = true;");
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    #[test]
    fn test_parse_bool_param_multiline_a() {
        let item = CompleteStr("allow.mount;\npersist;");
        let res = parse_bool_param_no_value(item);
        let ok = Ok((CompleteStr("\npersist;"), CompleteStr("allow.mount")));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_multiline_error() {
        let item = CompleteStr("allow.mount\n;");
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    // Parameters with values
    #[test]
    fn test_parse_param_with_value() {
        let item = CompleteStr("allow.mount = true;");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr(""),
                (CompleteStr("allow.mount"), CompleteStr("true"))
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_with_space() {
        let item = CompleteStr("exec.stop = \"/bin/sh /etc/rc.shutdown\";");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr(""),
                (CompleteStr("exec.stop"), CompleteStr("/bin/sh /etc/rc.shutdown"))
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_value_trailing_newline() {
        let item = CompleteStr("allow.mount = true;\n");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr("\n"),
                (CompleteStr("allow.mount"), CompleteStr("true"))
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value() {
        let item = CompleteStr("allow.mount = \"true\";");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr(""),
                (CompleteStr("allow.mount"), CompleteStr("true"))
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_trailing_newline() {
        let item = CompleteStr("allow.mount = \"true\";\n");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr("\n"),
                (CompleteStr("allow.mount"), CompleteStr("true"))
                ));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_no_spaces() {
        let item = CompleteStr("allow.mount=\"true\";");
        let res = parse_param_with_value(item);
        let ok = Ok((
                CompleteStr(""),
                (CompleteStr("allow.mount"), CompleteStr("true"))
                ));

        assert_eq!(res, ok);
    }

    // Integration testing, testing the main input parser.
    #[test]
    fn test_parse_input() {
        let input = CompleteStr(r#"
            allow.mount;
            persist;
            allow.raw_sockets = "1";
            exec.stop = "/bin/sh /etc/rc.shutdown";
            "#);

        let res = parse_input(input.into());

        let jc = vec![
            JailConf::ParamBool(JailParamBool{
                name: CompleteStr("allow.mount"),
            }),
            JailConf::ParamBool(JailParamBool{
                name: CompleteStr("persist"),
            }),
            JailConf::ParamValue(JailParamValue{
                name:  CompleteStr("allow.raw_sockets"),
                value: CompleteStr("1"),
            }),
            JailConf::ParamValue(JailParamValue{
                name:  CompleteStr("exec.stop"),
                value: CompleteStr("/bin/sh /etc/rc.shutdown"),
            }),
        ];

        let ok = Ok((CompleteStr(""), jc));

        assert_eq!(res, ok);
    }
}
