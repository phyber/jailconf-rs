use std::error;
use std::fmt;
use nom::*;
use nom::types::CompleteStr;

#[derive(Debug, PartialEq)]
pub enum CommentStyle {
    C,
    CPP,
    Shell,
}

#[derive(Debug, PartialEq)]
pub struct JailComment<'a> {
    comment: CompleteStr<'a>,
    style:   CommentStyle,
}

#[derive(Debug, PartialEq)]
pub struct JailParamBool<'a> {
    name: CompleteStr<'a>,
}

#[derive(Debug, PartialEq)]
pub struct JailParamValue<'a> {
    name:   CompleteStr<'a>,
    value:  CompleteStr<'a>,
    append: bool,
}

#[derive(Debug, PartialEq)]
pub struct JailBlock<'a> {
    name:   CompleteStr<'a>,
    params: Vec<JailConf<'a>>,
}

#[derive(Debug, PartialEq)]
pub enum JailConf<'a> {
    Block(JailBlock<'a>),
    Comment(JailComment<'a>),
    ParamBool(JailParamBool<'a>),
    ParamValue(JailParamValue<'a>),
}

#[derive(Debug)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "could not parse jail configuration")
    }
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        "could not parse jail configuration"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

// Parse a C style comment, eg:
// /*
//  * C style comment
//  */
named!(
    parse_comment_c_style<CompleteStr, JailComment>,
    do_parse!(
        res: delimited!(
            tag!("/*"),
            take_until!("*/"),
            tag!("*/")
        ) >>
        (JailComment{
            comment: res,
            style:   CommentStyle::C,
        })
    )
);

// Parse a CPP style comment, eg:
// // C++ style comment
named!(
    parse_comment_cpp_style<CompleteStr, JailComment>,
    do_parse!(
             tag!("//")        >>
        res: take_until!("\n") >>
        (JailComment{
            comment: res,
            style:   CommentStyle::CPP,
        })
    )
);

// Parse a shell style comment, eg:
// # Shell style comment
named!(
    parse_comment_shell_style<CompleteStr, JailComment>,
    do_parse!(
             tag!("#")         >>
        res: take_until!("\n") >>
        (JailComment{
            comment: res,
            style:   CommentStyle::Shell,
        })
    )
);

// Parse a valueless boolean in the style of:
//   - allow.mount;
//   - persist;
//   - etc;
//
// Other types of value will error.
named!(
    parse_bool_param_no_value<CompleteStr, JailParamBool>,
    do_parse!(
        name: take_until_either!(" +=;\n") >> // Consume until an interesting char
              not!(is_a!(" +=\n"))         >> // Ensure it's not a banned char
              char!(';')                   >> // Consume terminating ;
        (JailParamBool{
            name: name,
        })
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
    parse_param_with_value<CompleteStr, JailParamValue>,
    do_parse!(
        name:  take_until_either!(" +=;\n") >>
               not!(is_a!(";\n"))           >> // We don't want end of line yet
               space0                       >> // Optional spaces
        plus:  opt!(char!('+'))             >> // Optional +
               char!('=')                   >> // = is mandatory
               space0                       >> // Optional spaces
        value: delimited!(
                   opt_res!(tag!("\"")),        // Possible opening quote
                   take_until_either!("\";\n"), // value
                   opt_res!(tag!("\""))         // Possible closing quote
               )                            >>
               not!(is_a!("\n"))            >> // Ensure no new line yet
               char!(';')                   >> // Terminating ;
        (JailParamValue{
            name:   name,
            value:  value,
            append: plus.is_some(),
        })
    )
);

// Attempt to parse a jail block.
// eg.
// jailname {
//     ip4.addr = "127.0.1.1";
//     allow.mount;
//     persist;
// }
named!(
    parse_block<CompleteStr, JailConf>,
    do_parse!(
        name:  take_until_either!(" {;\n") >> // Read the name
               space0                      >> // Optional spaces
               not!(is_a!(";\n"))          >> // Invalid chars before block
               char!('{')                  >> // Mandatory opening {
        block: parse_input                 >> // Recursive parsing. Oh no.
               char!('}')                  >> // Mandatory terminating }
        (JailConf::Block(                     // JailBlock to return
            JailBlock{
                name:   name,
                params: block,
            }
        ))
    )
);

// Attempt to parse the given jail.conf input
named!(
    parse_input<CompleteStr, Vec<JailConf>>,
    do_parse!(
        // We attempt parsers many times until the input is exhausted.
        config: many0!(
            // Config could be in pretty much any order.
            // Surrounding whitespace will be trimmed.
            ws!(alt!(
                // Parse C style comments
                parse_comment_c_style => { |comment|
                    JailConf::Comment(comment)
                } |
                // Parse CPP style comments
                parse_comment_cpp_style => { |comment|
                    JailConf::Comment(comment)
                } |
                // Parse Shell style comments
                parse_comment_shell_style => { |comment|
                    JailConf::Comment(comment)
                } |
                // Parse a boolean parameter with no values.
                parse_bool_param_no_value => { |param|
                    JailConf::ParamBool(param)
                } |
                // Parse a parameter with a value.
                parse_param_with_value => { |param|
                    JailConf::ParamValue(param)
                } |
                // Parse a named jail block
                // Returns a JailConf::Block
                parse_block
            ))
        ) >>
        (config)
    )
);

// Public entry point into the parser.
pub fn parse(input: &str) -> Result<Vec<JailConf>, ParseError> {
    let res = parse_input(input.into());

    match res {
        Ok(r) => {
            let (_unparsed, parsed) = r;
            Ok(parsed)
        },
        Err(_e) => Err(ParseError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    // Valueless boolean params
    #[test]
    fn test_parse_bool_param_no_value() {
        let item = "allow.mount;".into();
        let res = parse_bool_param_no_value(item);
        let jc = JailParamBool{
            name: "allow.mount".into(),
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_trailing_newline() {
        let item = "allow.mount;\n".into();
        let res = parse_bool_param_no_value(item);
        let jc = JailParamBool{
            name: "allow.mount".into(),
        };
        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_no_value_with_value_error() {
        let item = "allow.mount = true;".into();
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    #[test]
    fn test_parse_bool_param_multiline_a() {
        let item = "allow.mount;\npersist;".into();
        let res = parse_bool_param_no_value(item);
        let jc = JailParamBool{
            name: "allow.mount".into(),
        };
        let ok = Ok(("\npersist;".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_bool_param_multiline_error() {
        let item = "allow.mount\n;".into();
        let res = parse_bool_param_no_value(item);

        assert!(res.is_err());
    }

    // Parameters with values
    #[test]
    fn test_parse_param_with_value() {
        let item = "allow.mount = true;".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:   "allow.mount".into(),
            value:  "true".into(),
            append: false,
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_with_space() {
        let item = "exec.stop = \"/bin/sh /etc/rc.shutdown\";".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:  "exec.stop".into(),
            value: "/bin/sh /etc/rc.shutdown".into(),
            append: false,
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_value_trailing_newline() {
        let item = "allow.mount = true;\n".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:  "allow.mount".into(),
            value: "true".into(),
            append: false,
        };
        let ok = Ok((CompleteStr("\n"), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value() {
        let item = "allow.mount = \"true\";".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:   "allow.mount".into(),
            value:  "true".into(),
            append: false,
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_emoji_value() {
        let item = "smile.emoji = \"😊\";".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:   "smile.emoji".into(),
            value:  "😊".into(),
            append: false,
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_trailing_newline() {
        let item = "allow.mount = \"true\";\n".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:   "allow.mount".into(),
            value:  "true".into(),
            append: false,
        };
        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_param_with_quoted_value_no_spaces() {
        let item = "allow.mount=\"true\";".into();
        let res = parse_param_with_value(item);
        let jc = JailParamValue{
            name:   "allow.mount".into(),
            value:  "true".into(),
            append: false,
        };
        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    // Integration testing, testing the main input parser.
    #[test]
    fn test_parse_input_no_blocks() {
        let input = indoc!(r#"
            allow.mount;
            persist;
            allow.raw_sockets = "1";
            exec.stop = "/bin/sh /etc/rc.shutdown";
            "#);

        let res = parse_input(input.into());

        let jc = vec![
            JailConf::ParamBool(JailParamBool{
                name: "allow.mount".into(),
            }),
            JailConf::ParamBool(JailParamBool{
                name: "persist".into(),
            }),
            JailConf::ParamValue(JailParamValue{
                name:   "allow.raw_sockets".into(),
                value:  "1".into(),
                append: false,
            }),
            JailConf::ParamValue(JailParamValue{
                name:   "exec.stop".into(),
                value:  "/bin/sh /etc/rc.shutdown".into(),
                append: false,
            }),
        ];

        let ok = Ok(("".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_input_block() {
        let input = indoc!(
        r#"
            nginx {
                host.hostname = "nginx";
            }
            "#);

        let res = parse_block(input.into());
        let jc = JailConf::Block(JailBlock{
            name: "nginx".into(),
            params: vec![
                JailConf::ParamValue(JailParamValue{
                    name:   "host.hostname".into(),
                    value:  "nginx".into(),
                    append: false,
                }),
            ],
        });

        let ok = Ok((CompleteStr("\n"), jc));
        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_input_full_conf() {
        let input = indoc!(
        r#"
            /*
             * Opening C style comment
             */
            allow.mount;                            // Allow mounting
            persist;                                /* Persist jail */
            allow.raw_sockets = "1";                # Allow raw sockets
            exec.stop = "/bin/sh /etc/rc.shutdown";

            // CPP style comment
            nginx {
                # Shell style comment
                host.hostname = "nginx";
            }

            # Multiple jails could be configured
            jail2 {
                persist;
            }
            "#);

        let res = parse_input(input.into());
        let jc = vec![
            JailConf::Comment(JailComment{
                comment: "\n * Opening C style comment\n ".into(),
                style:   CommentStyle::C,
            }),
            JailConf::ParamBool(JailParamBool{
                name: "allow.mount".into(),
            }),
            JailConf::Comment(JailComment{
                comment: " Allow mounting".into(),
                style:   CommentStyle::CPP,
            }),
            JailConf::ParamBool(JailParamBool{
                name: "persist".into(),
            }),
            JailConf::Comment(JailComment{
                comment: " Persist jail ".into(),
                style:   CommentStyle::C,
            }),
            JailConf::ParamValue(JailParamValue{
                name:   "allow.raw_sockets".into(),
                value:  "1".into(),
                append: false,
            }),
            JailConf::Comment(JailComment{
                comment: " Allow raw sockets".into(),
                style:   CommentStyle::Shell,
            }),
            JailConf::ParamValue(JailParamValue{
                name:   "exec.stop".into(),
                value:  "/bin/sh /etc/rc.shutdown".into(),
                append: false,
            }),
            JailConf::Comment(JailComment{
                comment: " CPP style comment".into(),
                style:   CommentStyle::CPP,
            }),
            JailConf::Block(JailBlock{
                name:  "nginx".into(),
                params: vec![
                    JailConf::Comment(JailComment{
                        comment: " Shell style comment".into(),
                        style:   CommentStyle::Shell,
                    }),
                    JailConf::ParamValue(JailParamValue{
                        name:   "host.hostname".into(),
                        value:  "nginx".into(),
                        append: false,
                    }),
                ],
            }),
            JailConf::Comment(JailComment{
                comment: " Multiple jails could be configured".into(),
                style:   CommentStyle::Shell,
            }),
            JailConf::Block(JailBlock{
                name:  "jail2".into(),
                params: vec![
                    JailConf::ParamBool(JailParamBool{
                        name: "persist".into(),
                    }),
                ],
            }),
        ];

        let ok = Ok(("".into(), jc));
        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_block() {
        let input = indoc!(
        r#"
            nginx {
                host.hostname = "nginx";
                path = "/usr/jails/nginx";
                ip4.addr = "lo1|127.0.1.1/32";
                ip6.addr += "lo1|fd00:0:0:1::1/64";
                ip4.addr += "em0|192.168.5.1/32";
                exec.start += "sleep  2 ";
                allow.raw_sockets = 0;
                exec.clean;
                exec.system_user = "root";
                exec.jail_user = "root";
                exec.start += "/bin/sh /etc/rc";
                exec.stop = "";
                exec.consolelog = "/var/log/jail_nginx_console.log";
                mount.fstab = "/etc/fstab.nginx";
                mount.devfs;
                mount.fdescfs;
                mount.procfs;
                allow.mount;
                allow.set_hostname = 0;
                allow.sysvipc = 0;
                enforce_statfs = "2";
            }
            "#);

        let res = parse_block(input.into());
        let jc = JailConf::Block(JailBlock{
            name:   "nginx".into(),
            params: vec![
                JailConf::ParamValue(JailParamValue{
                    name:   "host.hostname".into(),
                    value:  "nginx".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "path".into(),
                    value:  "/usr/jails/nginx".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "ip4.addr".into(),
                    value:  "lo1|127.0.1.1/32".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "ip6.addr".into(),
                    value:  "lo1|fd00:0:0:1::1/64".into(),
                    append: true,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "ip4.addr".into(),
                    value:  "em0|192.168.5.1/32".into(),
                    append: true,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.start".into(),
                    value:  "sleep  2 ".into(),
                    append: true,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "allow.raw_sockets".into(),
                    value:  "0".into(),
                    append: false,
                }),
                JailConf::ParamBool(JailParamBool{
                    name: "exec.clean".into(),
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.system_user".into(),
                    value:  "root".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.jail_user".into(),
                    value:  "root".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.start".into(),
                    value:  "/bin/sh /etc/rc".into(),
                    append: true,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.stop".into(),
                    value:  "".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "exec.consolelog".into(),
                    value:  "/var/log/jail_nginx_console.log".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "mount.fstab".into(),
                    value:  "/etc/fstab.nginx".into(),
                    append: false,
                }),
                JailConf::ParamBool(JailParamBool{
                    name: "mount.devfs".into(),
                }),
                JailConf::ParamBool(JailParamBool{
                    name: "mount.fdescfs".into(),
                }),
                JailConf::ParamBool(JailParamBool{
                    name: "mount.procfs".into(),
                }),
                JailConf::ParamBool(JailParamBool{
                    name: "allow.mount".into(),
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "allow.set_hostname".into(),
                    value:  "0".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "allow.sysvipc".into(),
                    value:  "0".into(),
                    append: false,
                }),
                JailConf::ParamValue(JailParamValue{
                    name:   "enforce_statfs".into(),
                    value:  "2".into(),
                    append: false,
                }),
            ],
        });

        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_block_with_invalid_semicolon_is_err() {
        let input = indoc!(r#"invalid; {
                persist;
            }"#);

        let res = parse_block(input.into());
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_block_with_invalid_newline_is_err() {
        let input = indoc!(r#"invalid
            {
                persist;
            }"#);

        let res = parse_block(input.into());
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_comment_c_style() {
        let input = indoc!(r#"
            /*
             * Test comment
             */
            "#);

        let res = parse_comment_c_style(input.into());
        let jc = JailComment{
            comment: "\n * Test comment\n ".into(),
            style:   CommentStyle::C,
        };

        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_coment_cpp_style() {
        let input = indoc!(r#"
            // CPP style comment
            "#);

        let res = parse_comment_cpp_style(input.into());
        let jc = JailComment{
            comment: " CPP style comment".into(),
            style:   CommentStyle::CPP,
        };

        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }

    #[test]
    fn test_parse_coment_shell_style() {
        let input = indoc!(r#"
            # Shell style comment
            "#);

        let res = parse_comment_shell_style(input.into());
        let jc = JailComment{
            comment: " Shell style comment".into(),
            style:   CommentStyle::Shell,
        };

        let ok = Ok(("\n".into(), jc));

        assert_eq!(res, ok);
    }
}
