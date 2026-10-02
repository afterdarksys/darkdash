use std::env;
use std::ffi::OsString;
use std::process;

use darkdash::{Error, parse_args, run};

fn main() {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let code = match parse_args(&args).and_then(run) {
        Ok(()) => 0,
        Err(Error::Usage) => {
            eprintln!("darkdash: usage");
            2
        }
        Err(err) => {
            eprintln!("darkdash: {err}");
            1
        }
    };
    process::exit(code);
}
