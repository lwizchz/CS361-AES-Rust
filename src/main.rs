use anyhow::{Context, Result};
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = aes::Opt::from_args();
    aes::do_with_args(&args)
        .context(format!("failed with args: {:?}", args))?;
    Ok(())
}
