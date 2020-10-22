use crate::wycheproof;
use crate::wycheproof::{case_result, description, hex_string};
use crate::TestInfo;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TestSuite {
    #[serde(flatten)]
    pub suite: wycheproof::Suite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(flatten)]
    pub group: wycheproof::Group,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(flatten)]
    pub case: wycheproof::Case,
    #[serde(with = "hex_string")]
    pub ikm: Vec<u8>,
    #[serde(with = "hex_string")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_string")]
    pub info: Vec<u8>,
    pub size: usize,
    #[serde(with = "hex_string")]
    pub okm: Vec<u8>,
}

pub fn generator(data: &[u8], algorithm: &str) -> Vec<TestInfo> {
    let suite: TestSuite = serde_json::from_slice(data).unwrap();
    assert_eq!(algorithm, suite.suite.algorithm);

    let mut infos = vec![];
    for g in &suite.test_groups {
        for tc in &g.tests {
            infos.push(TestInfo {
                data: vec![
                    tc.ikm.clone(),
                    tc.salt.clone(),
                    tc.info.clone(),
                    tc.okm.clone(),
                    vec![case_result(&tc.case)],
                ],
                desc: description(&suite.suite, &tc.case),
            });
        }
    }
    infos
}
