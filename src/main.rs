extern crate aes;

use structopt::StructOpt;

fn main() -> Result<(), aes::Error> {
    let args = aes::Opt::from_args();
    match aes::do_with_args(&args) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
