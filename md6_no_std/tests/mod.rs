#![no_std]

use digest::Digest;
use hex_literal::hex;

#[test]
fn test_md6_64() {
    let mut hasher = md6::Md6_64::new();
    hasher.update(b"md6 FTW");
    let output = hasher.finalize();

    assert!(output.to_vec() == hex!("47cda109418592ca"));
}

#[test]
fn test_md6_128() {
    let mut hasher = md6::Md6_128::new();
    hasher.update(b"aaaaaaaaaa");
    let output = hasher.finalize();

    assert!(output.to_vec() == hex!("623522019a5e40188a3b8956d44ea57d"));
}

#[test]
fn test_md6_224() {
    let mut hasher = md6::Md6_224::new();
    hasher.update(b"md6 FTW");
    let output = hasher.finalize();

    assert!(output.to_vec() == hex!("7952f429ebbe134d302939817eff92e099b16273a2c3b0741614d8ad"));
}

#[test]
fn test_md6_256() {
    let mut hasher = md6::Md6_256::new();
    hasher.update(b"aaaaaaaaaa");
    let output = hasher.finalize();

    assert!(
        output.to_vec() == hex!("3c74f2b9d89cf806cf0b529773ef09b8ed0b393afe166fa759f53d2cb6dfb40b")
    );
}

#[test]
fn test_md6_384() {
    let mut hasher = md6::Md6_384::new();
    hasher.update(b"md6 FTW");
    let output = hasher.finalize();

    assert!(output.to_vec() == hex!("7a4e8ecd1035ccdf00567595c15aa5a382fef2b6a4ec4bc609e0c655887b1c05e10eee223dd6c0ba5fa4a46159c70757"));
}

#[test]
fn test_md6_512() {
    let mut hasher = md6::Md6_512::new();
    hasher.update(b"aaaaaaaaaa");
    let output = hasher.finalize();

    assert!(output.to_vec() == hex!("c4451dcd12d3847e1f2408ed3c9cc2f79a179ddf5a0a9246b68adcf918bbcea67f6c8721cc226599d587313895b8a8d53881061014b6444f3d3464b03602ecc2"));
}
