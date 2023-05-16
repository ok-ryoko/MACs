use digest::{MacXof, KeyCustomInit};
use kmac::{Kmac128, Kmac256};
use hex_literal::hex;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf

#[test]
fn kmac128_test_1() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let mut mac = Kmac128::new_from_slice(&key);

    let data = hex!("00010203");
    mac.update(&data);

    let mut result = [0u8; 32];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        e5780b0d3ea6f7d3a429c5706aa43a00
        fadbd7d49628839e3187243f456ee14e
    ");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn kmac128_test_2() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let customization = b"My Tagged Application";
    let mut mac = Kmac128::new_with_customization(&key, customization);

    let data = hex!("00010203");
    mac.update(&data);

    let mut result = [0u8; 32];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        3b1fba963cd8b0b59e8c1a6d71888b71
        43651af8ba0a7070c0979e2811324aa5
    ");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn kmac128_test_3() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let customization = b"My Tagged Application";
    let mut mac = Kmac128::new_with_customization(&key, customization);

    let data = hex!("
        000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        303132333435363738393a3b3c3d3e3f
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
        606162636465666768696a6b6c6d6e6f
        707172737475767778797a7b7c7d7e7f
        808182838485868788898a8b8c8d8e8f
        909192939495969798999a9b9c9d9e9f
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
        c0c1c2c3c4c5c6c7
    ");
    mac.update(&data);

    let mut result = [0u8; 32];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        1f5b4e6cca02209e0dcb5ca635b89a15
        e271ecc760071dfd805faa38f9729230
    ");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn kmac256_test_1() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let customization = b"My Tagged Application";
    let mut mac = Kmac256::new_with_customization(&key, customization);

    let data = hex!("00010203");
    mac.update(&data);

    let mut result = [0u8; 64];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        20c570c31346f703c9ac36c61c03cb64
        c3970d0cfc787e9b79599d273a68d2f7
        f69d4cc3de9d104a351689f27cf6f595
        1f0103f33f4f24871024d9c27773a8dd
    ");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn kmac256_test_2() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let mut mac = Kmac256::new_from_slice(&key);

    let data = hex!("
        000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        303132333435363738393a3b3c3d3e3f
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
        606162636465666768696a6b6c6d6e6f
        707172737475767778797a7b7c7d7e7f
        808182838485868788898a8b8c8d8e8f
        909192939495969798999a9b9c9d9e9f
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
        c0c1c2c3c4c5c6c7
    ");
    mac.update(&data);

    let mut result = [0u8; 64];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        75358cf39e41494e949707927cee0af2
        0a3ff553904c86b08f21cc414bcfd691
        589d27cf5e15369cbbff8b9a4c2eb178
        00855d0235ff635da82533ec6b759b69
    ");
    assert_eq!(result[..], expected[..]);
}

#[test]
fn kmac256_test_3() {
    let key = hex!("
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
    ");
    let customization = b"My Tagged Application";
    let mut mac = Kmac256::new_with_customization(&key, customization);

    let data = hex!("
        000102030405060708090a0b0c0d0e0f
        101112131415161718191a1b1c1d1e1f
        202122232425262728292a2b2c2d2e2f
        303132333435363738393a3b3c3d3e3f
        404142434445464748494a4b4c4d4e4f
        505152535455565758595a5b5c5d5e5f
        606162636465666768696a6b6c6d6e6f
        707172737475767778797a7b7c7d7e7f
        808182838485868788898a8b8c8d8e8f
        909192939495969798999a9b9c9d9e9f
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
        c0c1c2c3c4c5c6c7
    ");
    mac.update(&data);

    let mut result = [0u8; 64];
    mac.finalize_xof_into(&mut result);
    let expected = hex!("
        b58618f71f92e1d56c1b8c55ddd7cd18
        8b97b4ca4d99831eb2699a837da2e4d9
        70fbacfde50033aea585f1a2708510c3
        2d07880801bd182898fe476876fc8965
    ");
    assert_eq!(result[..], expected[..]);
}
