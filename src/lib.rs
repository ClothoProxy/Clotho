#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(trivial_casts, trivial_numeric_casts)]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(unused_qualifications)]

//! This crate provides a library and binaries for identitying the origin of an AWS `Sigv4` request.
//! The only documented way to achieve this is by calling the STS endpoint
//! <https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html> . However, it
//! turns out the AWS account ID is encoded in the AWS Access Key Id, as discovered by[a short note on AWS KEY ID by Tal Be'ery](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489). .  
//! Instead of making an HTTP request for each authorization request, we can "extract" the AWS
//! accound ID offline.
//!
//! This is very useful for proxies and other use cases where the volume and response times of
//! requests are critical.
//!
//!
use chrono::NaiveDate;
use data_encoding::BASE32;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use thiserror::Error;

/// YAML container struct
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct Config {
    accounts: HashMap<String, Account>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Account {
    regions: HashMap<String, Services>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Services {
    services: Vec<String>,
}

/// Representation of an AWS Credential
/// used when unpacking the components of a `Sigv4`
#[derive(Debug, PartialEq, Eq)]
pub struct AWSCredential {
    /// The access_key_id included in the request
    pub access_key_id: String,
    /// Derived from the access_key_id
    pub account_id: String,
    /// The date included in the Authorization header
    pub date: NaiveDate,
    /// The region included in the Authorization header
    pub region: String,
    /// The AWS Service included in the Authorization header
    pub service: String,
}

impl AWSCredential {
    const BYTE_MASK: u64 = 0x7fff_ffff_ff80;
    const ANY: &str = "*";

    /// Return the information held in AWS `Sigv4` from the `Authorization` header
    /// Use this function to pass the whole `Authorization` header
    ///
    /// # Arguments
    /// * `header` - A string slice that is the `Authorization` header. For example:
    /// > Authorization: AWS4-HMAC-SHA256
    /// > Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
    /// > SignedHeaders=host;range;x-amz-date,
    /// > Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
    ///
    /// # Errors
    /// - `AWSCredentialError::AccessKeyIDLengthError` - if the key id is not of length
    /// - `AWSCredentialError::AccountMissingFromAccessKeyId` - if the key cannot be decoded
    /// - `AWSCredentialError::AuthHeaderMissingParts` - if the authorization header is not correct
    /// - `AWSCredentialError::Base32DecodeError` - if the Base32 decode fails
    /// - `AWSCredentialError::CredentialComponentMissingParts` - if the auth header is not complete
    /// - `AWSCredentialError::DateParseError` - if the date cannot be parsed
    ///
    pub fn new_from_http_authz(header: &str) -> Result<AWSCredential, AWSCredentialError> {
        let start = header
            .find("Credential=")
            .ok_or_else(|| AWSCredentialError::AuthHeaderMissingParts(header.to_string()))?;

        let value_start = start + 11; //"Credential=".len();

        let end = header[value_start..].find(',').unwrap_or(header.len());

        let header = Ok(&header[value_start..value_start + end])?;
        Ok(AWSCredential::new(header))?
    }

    /// Returns the information held in an AWS `Sigv4` authorization,
    /// extracting the embedded `account_id` from the `access_key_id`
    /// Will not validate the `region` or the `date`.
    ///
    /// # Arguments
    /// * `credential` - A string slice that is the value of the `Credential` component of the
    /// `Authorization` header. For example:
    /// > Authorization: AWS4-HMAC-SHA256
    /// > Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
    /// > SignedHeaders=host;range;x-amz-date,
    /// `credential` takes the value of `Credential`, i.e. `AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request`
    /// See: <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html#sigv4-auth-header-overview>
    /// # Examples
    /// ```
    /// # use clotho::{AWSCredential, AWSCredentialError};
    /// # fn main() {
    /// let creds =
    /// AWSCredential::new("AKIAWNIPTZAB2WR3H4UP/20230318/us-east-1/iam/aws4_request").unwrap();
    /// println!("{:?}", creds.account_id);
    /// # }
    /// ```
    /// # Errors
    /// - `AWSCredentialError::AccessKeyIDLengthError` - if the key id is not of length
    /// - `AWSCredentialError::AccountMissingFromAccessKeyId` - if the key cannot be decoded
    /// - `AWSCredentialError::Base32DecodeError` - if the Base32 decode fails
    /// - `AWSCredentialError::CredentialComponentMissingParts` - if the auth header is not complete
    /// - `AWSCredentialError::DateParseError` - if the date cannot be parsed
    pub fn new(credential: &str) -> Result<AWSCredential, AWSCredentialError> {
        let parts: Vec<&str> = credential.split('/').collect();

        if parts.len() != 5 {
            return Err(AWSCredentialError::CredentialComponentMissingParts(
                credential.to_string(),
            ));
        }

        let account_id = AWSCredential::get_account_id(parts[0].as_bytes())?;
        let date = AWSCredential::parse_date(parts[1])?;
        let service = parts[3].to_string();

        Ok(AWSCredential {
            access_key_id: parts[0].to_string(),
            region: parts[2].to_string(),
            account_id,
            date,
            service,
        })
    }

    /// Check if the `Sigv4` containing request should be allowed according to the YAML allowlist config
    /// # Arguments
    /// * `&config` - The contents of the config file returned by `read_yaml`
    ///
    #[must_use]
    pub fn is_request_allowed(&self, config: &Config) -> bool {
        let Some(account) = &config
            .accounts
            .get(&self.account_id)
            .or_else(|| config.accounts.get(Self::ANY))
        else {
            return false;
        };

        let Some(services) = account
            .regions
            .get(&self.region)
            .or_else(|| account.regions.get(Self::ANY))
        else {
            return false;
        };

        if services.services.contains(&self.service)
            || services.services.contains(&Self::ANY.to_owned())
        {
            return true;
        }

        false
    }

    /// Returns `NaiveDate` from "%Y%m%d"
    /// # Errors
    /// - `AWSCredentialError::DateParseError` - When date is not in the format
    fn parse_date(date_str: &str) -> Result<NaiveDate, AWSCredentialError> {
        match NaiveDate::parse_from_str(date_str, "%Y%m%d") {
            Ok(date) => Ok(date),
            Err(e) => Err(AWSCredentialError::DateParseError(e.to_string())),
        }
    }

    /// Pass the `access_key_id` as a `u8`
    /// returns the `account_id` as a 12 digit `String`
    /// # Arguments
    /// * `access_key_id` - A &[u8] containing the `access_key_id`
    /// an access key id is at least 12 digits long
    fn get_account_id(access_key_id: &[u8]) -> Result<String, AWSCredentialError> {
        if access_key_id.len() <= 12 {
            return Err(AWSCredentialError::AccessKeyIDLengthError(
                access_key_id.len().to_string(),
            ));
        }
        let key_part = &access_key_id[4..];
        match BASE32.decode_len(key_part.len()) {
            Ok(decode_len) => {
                if decode_len != 10 {
                    return Err(AWSCredentialError::AccountMissingFromAccessKeyId(
                        decode_len.to_string(),
                    ));
                }
            }

            Err(e) => return Err(AWSCredentialError::Base32DecodeError(e.to_string())),
        };

        let mut output: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _ = BASE32.decode_mut(key_part, &mut output);

        let decodedb = u64::from_be_bytes([
            0, 0, output[0], output[1], output[2], output[3], output[4], output[5],
        ]);

        let e = (decodedb & AWSCredential::BYTE_MASK) >> 7;
        Ok(format!("{e:0>12}"))
    }

    /// Read the YAML config from the `file_path`
    /// # Arguments
    /// * `file_path` - location of the file
    /// # Errors
    /// # * `ConfigError` - File read error or Yaml parsing error  
    pub fn read_config(&self, file_path: PathBuf) -> Result<Config, ConfigError> {
        let mut file = File::open(file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(serde_yaml::from_str(&contents)?)
    }
}

/// Errors when constructing a new `AWSCredential`
#[non_exhaustive]
#[derive(Error, Debug, PartialEq)]
pub enum AWSCredentialError {
    /// Provided Access Key ID is invalid
    #[error("Access Key ID invalid length, expected more than 12 chars got: {0}")]
    AccessKeyIDLengthError(String),
    /// The Authorization header is missing parts
    #[error("Auth header missing parts: {0}")]
    AuthHeaderMissingParts(String),
    #[error("Could not find account id in access key: {0}")]
    /// Couldn't extract Account ID from
    AccountMissingFromAccessKeyId(String),
    #[error("Base32 Decode Error {0}")]
    /// Decoding Base32 failed
    Base32DecodeError(String),
    #[error("Credential component missing parts: {0}")]
    /// The credential component of the Authorization header is missing parts
    CredentialComponentMissingParts(String),
    #[error("Could not parse date {0}")]
    /// Failed to parse the date, not in %Y%m%d format
    DateParseError(String),
}

/// Errors for loading the YAML config
#[derive(Error, Debug)]
pub enum ConfigError {
    /// IO Error when trying to read file
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serde_YAML error with parsing
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),
}

#[cfg(test)]
mod tests {

    use crate::AWSCredentialError;

    use super::*;
    //use std::fs::File;
    use std::io::Write;
    //use std::path::Path;

    fn temp_file_with_content(content: &str) -> PathBuf {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{}", content).unwrap();
        file.into_temp_path().to_path_buf()
    }

    #[test]
    fn correct_authz_header() {
        let authz_header = r#"
    Authorization: AWS4-HMAC-SHA256 
    Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, 
    SignedHeaders=host;range;x-amz-date,
    Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
        "#;
        let acc = AWSCredential::new_from_http_authz(authz_header).unwrap();
        assert_eq!(acc.account_id, "581039954779".to_string());
        assert_eq!(acc.region, "us-east-1".to_string());
        assert_eq!(
            acc.date.format("%Y-%m-%d").to_string(),
            "2013-05-24".to_string()
        );
    }
    #[test]
    fn wrong_authz_header() {
        let authz_header = r#"
    Authorization: Credent=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, 
        "#;
        let acc = AWSCredential::new_from_http_authz(authz_header);
        assert_eq!(
            acc,
            Err(AWSCredentialError::AuthHeaderMissingParts(
                authz_header.to_string()
            ))
        )
    }
    #[test]
    fn empty_authz_header() {
        let acc = AWSCredential::new_from_http_authz("");
        assert_eq!(
            acc,
            Err(AWSCredentialError::AuthHeaderMissingParts("".to_string()))
        )
    }
    #[test]
    fn long_authz_header() {
        let long_string = "a".repeat(10000);
        let acc = AWSCredential::new_from_http_authz(&long_string);
        assert_eq!(
            acc,
            Err(AWSCredentialError::AuthHeaderMissingParts(
                long_string.to_string()
            ))
        )
    }
    #[test]
    fn correct_credential_header() {
        let accone =
            AWSCredential::new("ASIAQNZGKIQY56JQ7WML/20221228/eu-west-1/ec2/aws4_request").unwrap();

        assert_eq!(accone.account_id, "029608264753".to_string());
        assert_eq!(accone.region, "eu-west-1".to_string());
        assert_eq!(
            accone.date.format("%Y-%m-%d").to_string(),
            "2022-12-28".to_string()
        );
    }

    #[test]
    fn wrong_credential_header() {
        let acc = AWSCredential::new("ASIAQNZGKI/20221228/eu-west-1/ec2/aws4_request");

        assert_eq!(
            acc,
            Err(AWSCredentialError::AccessKeyIDLengthError("10".to_string()))
        )
    }

    #[test]
    fn wrong_date_format() {
        let d = AWSCredential::parse_date("20221228").unwrap();
        assert_eq!(d.format("%Y%m%d").to_string(), "20221228".to_string())
    }
    #[test]
    fn wrong_date_credential_header() {
        let acc = AWSCredential::new("ASIAQNZGKIQY56JQ7WML/202228/eu-west-1/ec2/aws4_request");
        assert_eq!(
            acc,
            Err(AWSCredentialError::DateParseError(
                "premature end of input".to_string()
            ))
        )
    }

    #[test]
    fn empty_credential_header() {
        let acc = AWSCredential::new("");

        assert_eq!(
            acc,
            Err(AWSCredentialError::CredentialComponentMissingParts(
                "".to_string()
            ))
        )
    }

    #[test]
    fn known_account() {
        let accone = AWSCredential::get_account_id(b"ASIAQNZGKIQY56JQ7WML");
        assert_eq!(accone.unwrap(), "029608264753".to_string());
    }

    #[test]
    fn known_account_zero() {
        let accone = AWSCredential::get_account_id(b"ASIAAAAAAAAAAAAAAAAA");

        assert_eq!(accone.unwrap(), "000000000000".to_string());
    }

    #[test]
    fn bad_account_input() {
        let acc = AWSCredential::get_account_id(b"A");

        assert_eq!(
            acc,
            Err(AWSCredentialError::AccessKeyIDLengthError("1".to_string()))
        );
    }

    #[test]
    fn long_account_input() {
        let long_string = "a".repeat(1000);
        let acc = AWSCredential::get_account_id(long_string.as_bytes());

        assert_eq!(
            acc,
            Err(AWSCredentialError::Base32DecodeError(
                "invalid length at 992".to_string()
            ))
        )
    }

    #[test]
    fn test_read_yaml_invalid() {
        // Arrange
        let yaml_content = "not a valid yaml"; // invalid YAML content
        let file_path = temp_file_with_content(yaml_content);

        let aws_creds =
            AWSCredential::new("ASIAQNZGKIQY56JQ7WML/20221228/eu-west-1/ec2/aws4_request").unwrap();

        let result = aws_creds.read_config(file_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_read_yaml_file_not_found() {
        // Arrange
        let file_path = PathBuf::from("non_existent_file.yaml");
        let aws_creds =
            AWSCredential::new("ASIAQNZGKIQY56JQ7WML/20221228/eu-west-1/ec2/aws4_request").unwrap();

        let result = aws_creds.read_config(file_path);

        assert!(result.is_err());
    }
}
