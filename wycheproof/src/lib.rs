//! Helpers for retrieving Wycheproof test vectors.

use serde::Deserialize;

/// `Suite` represents the common elements of the top level object in a Wycheproof json
/// file.  Implementations should embed (using `#[serde(flatten)]`) `Suite` in a struct
/// that strongly types the `testGroups` field.
#[derive(Debug, Deserialize)]
pub struct Suite {
    pub algorithm: String,
    #[serde(rename = "generatorVersion")]
    pub generator_version: String,
    #[serde(rename = "numberOfTests")]
    pub number_of_tests: i32,
    pub notes: std::collections::HashMap<String, String>,
}

/// `Group` represents the common elements of a testGroups object in a Wycheproof suite.
/// Implementations should embed (using `#[serde(flatten)]`) Group in a struct that
/// strongly types its list of cases.
#[derive(Debug, Deserialize)]
pub struct Group {
    #[serde(rename = "type")]
    pub group_type: String,
}

/// `Result` represents the possible result values for a Wycheproof test case.
#[derive(Debug, PartialEq, Eq)]
pub enum CaseResult {
    /// Test case is valid, the crypto operation should succeed.
    Valid,
    /// Test case is invalid; the crypto operation should fail.
    Invalid,
    /// Test case is valid, but uses weak parameters; the crypto operation might succeed
    /// or fail depending on how strict the library is.
    Acceptable,
}

impl std::fmt::Display for CaseResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CaseResult::Valid => "valid",
                CaseResult::Invalid => "invalid",
                CaseResult::Acceptable => "acceptable",
            }
        )
    }
}

/// `Case` represents the common elements of a tests object in a Wycheproof group.
/// Implementations should embed (using `#[serde(flatten)]`) `Case` in a struct that
/// contains fields specific to the test type.
#[derive(Debug, Deserialize)]
pub struct Case {
    #[serde(rename = "tcId")]
    pub case_id: i32,
    pub comment: String,
    #[serde(with = "case_result")]
    pub result: CaseResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// Retrieve Wycheproof test vectors from the given filename in a Wycheproof repo.
///
/// The location of the Wycheproof repository is given by the `WYCHEPROOF_DIR` environment variable if set; otherwise
/// `${OUT_DIR}/wycheproof` will be used.
pub fn wycheproof_data(filename: &str) -> Vec<u8> {
    let wycheproof_dir = std::env::var("WYCHEPROOF_DIR")
        .unwrap_or(concat!(env!("OUT_DIR"), "/wycheproof").to_string());
    std::fs::read(std::path::Path::new(&wycheproof_dir).join(filename)).unwrap_or_else(|_| {
        panic!(
            "Test vector file {} not found under {}",
            filename, wycheproof_dir
        )
    })
}

pub mod hex_string {
    //! Manual JSON deserialization implementation for hex strings.
    use serde::Deserialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        ::hex::decode(&s).map_err(|_e| {
            serde::de::Error::invalid_value(serde::de::Unexpected::Str(&s), &"hex data expected")
        })
    }
}

pub mod case_result {
    //! Manual JSON deserialization for a `result` enum.
    use serde::Deserialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<super::CaseResult, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_ref() {
            "valid" => Ok(super::CaseResult::Valid),
            "invalid" => Ok(super::CaseResult::Invalid),
            "acceptable" => Ok(super::CaseResult::Acceptable),
            _ => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&s),
                &"unexpected result value",
            )),
        }
    }
}
