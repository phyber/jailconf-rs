# `jailconf-rs`

This is a simple library for parsing [FreeBSD] [`jail.conf(5)`] files using
Rust.  It should parse basic [`jail(8)`] configurations as shown in the
[example].

The parsers are written using [nom].

## Usage

The API and types returned by the library are currently in a state of flux.
The errors returned also require some work.  Usage isn't recommended at this
time.

## Testing

All types parsed by the library have tests written, with an overall integration
test for parsing a full jail configuration.

## Future

It is my intent to create a [serde] library to go along with this to allow
simple manipulation of jail configurations from Rust.

[FreeBSD]: https://www.freebsd.org/
[example]: jail.ioc-test-jail.conf
[nom]: https://crates.io/crates/nom
[serde]: https://crates.io/crates/serde
[`jail(8)`]: https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=8
[`jail.conf(5)`]: https://www.freebsd.org/cgi/man.cgi?query=jail.conf&sektion=5
