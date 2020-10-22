use crate::wycheproof;
use crate::wycheproof::{case_result, description, hex_string};
use crate::TestInfo;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestSuite {
    #[serde(flatten)]
    pub suite: wycheproof::Suite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
pub struct TestGroup {
    #[serde(flatten)]
    pub group: wycheproof::Group,
    #[serde(rename = "ivSize")]
    pub iv_size: u32,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    #[serde(rename = "tagSize")]
    pub tag_size: u32,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
pub struct TestCase {
    #[serde(flatten)]
    pub case: wycheproof::Case,
    #[serde(with = "hex_string")]
    pub aad: Vec<u8>,
    #[serde(with = "hex_string")]
    pub ct: Vec<u8>,
    #[serde(with = "hex_string")]
    pub iv: Vec<u8>,
    #[serde(with = "hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "hex_string")]
    pub tag: Vec<u8>,
}

pub fn aes_gcm_variant(data: &[u8], algorithm: &str) -> Vec<TestInfo> {
    generator(data, algorithm, &[16, 32], 12)
}
pub fn chacha20_poly1305(data: &[u8], algorithm: &str) -> Vec<TestInfo> {
    generator(data, algorithm, &[32], 12)
}

pub fn xchacha20_poly1305(data: &[u8], algorithm: &str) -> Vec<TestInfo> {
    generator(data, algorithm, &[32], 24)
}

fn generator(data: &[u8], algorithm: &str, key_sizes: &[u32], iv_size: u32) -> Vec<TestInfo> {
    let suite: TestSuite = serde_json::from_slice(data).unwrap();
    assert_eq!(algorithm, suite.suite.algorithm);

    let mut infos = vec![];
    for g in &suite.test_groups {
        for tc in &g.tests {
            if !key_sizes.contains(&(g.key_size / 8)) {
                println!(" skipping tests for key_size={}", g.key_size);
                continue;
            }
            if (g.iv_size / 8) != iv_size {
                println!(" skipping tests for iv_size={}", g.iv_size);
                continue;
            }
            let mut combined_ct = Vec::new();
            combined_ct.extend_from_slice(&tc.ct);
            combined_ct.extend_from_slice(&tc.tag);

            infos.push(TestInfo {
                data: vec![
                    tc.key.clone(),
                    tc.iv.clone(),
                    tc.aad.clone(),
                    tc.msg.clone(),
                    combined_ct,
                    vec![case_result(&tc.case)],
                ],
                desc: description(&suite.suite, &tc.case),
            });
        }
    }
    infos
}
