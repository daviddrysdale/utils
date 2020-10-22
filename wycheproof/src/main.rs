//! Tool to convert Wycheproof test vectors to raw hex format

use maplit::btreemap;
use std::collections::BTreeMap;
use std::io::Write;
use structopt::StructOpt;

mod aead;
mod aes_cmac;
mod aes_siv;
mod ecdsa;
mod ed25519;
mod hkdf;
mod prf;
mod wycheproof;

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(
        long,
        help = "The location of the Wycheproof repository",
        default_value = ""
    )]
    wycheproof_dir: String,

    #[structopt(
        long,
        help = "Algorithm to convert to raw hex format",
        default_value = ""
    )]
    algorithm: String,

    #[structopt(long, help = "Destination file", default_value = "")]
    out: String,

    #[structopt(
        long,
        help = "Destination file for test descriptions (one per line)",
        default_value = ""
    )]
    txt: String,
}

/// Test information
pub struct TestInfo {
    /// Raw data for the tests.
    pub data: Vec<Vec<u8>>,
    /// Test case description.
    pub desc: String,
}

/// Generator function which takes input parameters:
///  - contents of Wycheproof test data file
///  - algorithm name
/// and returns the raw contents, together  with a list of test identifiers (one per entry).
type BlbGenerator = fn(&[u8], &str) -> Vec<TestInfo>;

struct Algorithm {
    pub file: &'static str,
    pub generator: BlbGenerator,
}

fn main() {
    let opts = Opts::from_args();
    if opts.wycheproof_dir.is_empty() {
        panic!("Need location of wycheproof data");
    }

    let algorithms: BTreeMap<String, Algorithm> = btreemap! {
        "AES-GCM".to_string() => Algorithm{file: "aes_gcm_test.json", generator: aead::aes_gcm_variant},
        "AES-GCM-SIV".to_string() => Algorithm{file: "aes_gcm_siv_test.json", generator: aead::aes_gcm_variant},
        "CHACHA20-POLY1305".to_string() => Algorithm{file: "chacha20_poly1305_test.json", generator: aead::chacha20_poly1305},
        "XCHACHA20-POLY1305".to_string() => Algorithm{file: "xchacha20_poly1305_test.json", generator: aead::xchacha20_poly1305},
        "AES-SIV-CMAC".to_string() => Algorithm{file: "aes_siv_cmac_test.json", generator: aes_siv::generator},
        "AES-CMAC".to_string() => Algorithm{file: "aes_cmac_test.json", generator: aes_cmac::generator},
        "HKDF-SHA-1".to_string() => Algorithm{file: "hkdf_sha1_test.json", generator: hkdf::generator},
        "HKDF-SHA-256".to_string() => Algorithm{file: "hkdf_sha256_test.json", generator: hkdf::generator},
        "HKDF-SHA-384".to_string() => Algorithm{file: "hkdf_sha384_test.json", generator: hkdf::generator},
        "HKDF-SHA-512".to_string() => Algorithm{file: "hkdf_sha512_test.json", generator: hkdf::generator},
        "HMAC-SHA-1".to_string() => Algorithm{file: "hmac_sha1_test.json", generator: prf::generator},
        "HMAC-SHA-256".to_string() => Algorithm{file: "hmac_sha256_test.json", generator: prf::generator},
        "HMAC-SHA-384".to_string() => Algorithm{file: "hmac_sha384_test.json", generator: prf::generator},
        "HMAC-SHA-512".to_string() => Algorithm{file: "hmac_sha512_test.json", generator: prf::generator},
        "EDDSA".to_string() => Algorithm{file: "eddsa_test.json", generator: ed25519::generator},
        "ECDSA".to_string() => Algorithm{file: "ecdsa_test.json", generator: ecdsa::generator},
    };

    let algo = algorithms.get(&opts.algorithm).unwrap_or_else(|| {
        panic!(
            "Unrecognized algorithm '{}'; available algorithms are: {}",
            opts.algorithm,
            algorithms
                .keys()
                .cloned()
                .collect::<Vec<String>>()
                .join(" ")
        )
    });

    if opts.out.is_empty() {
        panic!("Need a destination file");
    }
    let data = wycheproof::data(&opts.wycheproof_dir, &algo.file);

    let infos = (algo.generator)(&data, &opts.algorithm);
    let mut out_file = std::fs::File::create(opts.out).unwrap();
    for info in &infos {
        for blob in &info.data {
            out_file.write_all(hex::encode(blob).as_bytes()).unwrap();
            out_file.write_all(b"\n").unwrap();
        }
    }

    if !opts.txt.is_empty() {
        let mut txt_file = std::fs::File::create(opts.txt).unwrap();
        for info in &infos {
            writeln!(&mut txt_file, "{}", info.desc).unwrap();
        }
    }
}
