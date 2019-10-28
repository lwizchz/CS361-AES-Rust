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

#[test]
fn test1() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B128,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key1".to_string(),
        inputfile: "tests/plaintext1".to_string(),
        outputfile: "tests/decrypted1".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext1".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[test]
fn test2() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B256,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key2".to_string(),
        inputfile: "tests/plaintext2".to_string(),
        outputfile: "tests/decrypted2".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext2".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[test]
fn test3() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B256,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key3".to_string(),
        inputfile: "tests/plaintext3".to_string(),
        outputfile: "tests/decrypted3".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext3".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[test]
fn test4() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B256,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key4".to_string(),
        inputfile: "tests/plaintext4".to_string(),
        outputfile: "tests/decrypted4".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext4".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[test]
fn test5() -> Result<(), aes::Error> {
    let args = aes::Opt {
        keysize: aes::Keysize::B256,
        mode: aes::Mode::Encrypt,
        verbose: false,

        keyfile: "tests/key5".to_string(),
        inputfile: "tests/plaintext5".to_string(),
        outputfile: "tests/decrypted5".to_string(),
    };

    match verify_crypto(args, "tests/ciphertext5".to_string()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
