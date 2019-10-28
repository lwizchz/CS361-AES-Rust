extern crate aes;

fn verify_crypto(mut args: aes::Opt, cipherfile: String) -> Result<(aes::StateArray, aes::StateArray, aes::StateArray), aes::Error> {
    let plaintext = aes::StateArray::from_file(&args.inputfile)?;

    let outputfile = args.outputfile;
    args.mode = aes::Mode::Encrypt;
    args.outputfile = cipherfile.clone();
    let ciphertext: aes::StateArray = aes::do_with_args(&args)?;

    args.mode = aes::Mode::Decrypt;
    args.inputfile = cipherfile;
    args.outputfile = outputfile;
    let decrypted: aes::StateArray = aes::do_with_args(&args)?;

    assert_eq!(plaintext, decrypted);

    Ok((plaintext, ciphertext, decrypted))
}

#[test]
fn test0() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B128,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key0".to_string(),
        inputfile: "tests/plaintext0".to_string(),
        outputfile: "tests/decrypted0".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext0".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
