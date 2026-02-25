// Copyright (year) Beijing Volcano Engine Technology Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};

// RFC 3986 unreserved characters: A-Z a-z 0-9 - _ . ~
// We encode everything EXCEPT these characters.
const RFC3986_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

type HmacSha256 = Hmac<Sha256>;

// ============================================================
// Credentials — replace with your own Access Key and Secret Key
// ============================================================
const ACCESS_KEY: &str = "YOUR AK";
const SECRET_KEY: &str = "YOUR SK";

// ============================================================
// Helper functions
// ============================================================

/// Compute SHA-256 hex digest of the given bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256 and return the raw bytes.
fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Derive the signing key by chaining HMAC-SHA256 operations.
///
/// kDate    = HMAC-SHA256(secret_key, date)
/// kRegion  = HMAC-SHA256(kDate,      region)
/// kService = HMAC-SHA256(kRegion,    service)
/// kSigning = HMAC-SHA256(kService,   "request")
fn derive_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(secret_key.as_bytes(), date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    hmac_sha256(&k_service, "request")
}

/// RFC 3986 percent-encode a string.
fn rfc3986_encode(input: &str) -> String {
    utf8_percent_encode(input, RFC3986_ENCODE_SET).to_string()
}

/// Build a sorted, percent-encoded query string from key-value pairs.
fn build_sorted_query_string(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (rfc3986_encode(k), rfc3986_encode(v)))
        .collect();
    encoded.sort();

    encoded
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

// ============================================================
// Core signing + request function
// ============================================================

/// Signs and sends an HTTP request using the Volcano Engine V4 signature.
fn do_request(
    method: &str,
    endpoint: &str,
    region: &str,
    service: &str,
    query_params: &[(&str, &str)],
    body: &str,
    content_type: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let is_get = method == "GET";
    let body_for_sign = if is_get { "" } else { body };

    // --- Step 1: Prepare signing materials ---------------------------------
    let now = Utc::now();
    let x_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let short_x_date = &x_date[..8];

    let x_content_sha256 = sha256_hex(body_for_sign.as_bytes());
    let signed_headers = "content-type;host;x-content-sha256;x-date";

    // --- Step 2: Build Canonical Request -----------------------------------
    let sorted_query = build_sorted_query_string(query_params);

    let canonical_request = [
        method,
        "/",
        &sorted_query,
        &format!("content-type:{content_type}"),
        &format!("host:{endpoint}"),
        &format!("x-content-sha256:{x_content_sha256}"),
        &format!("x-date:{x_date}"),
        "", // empty line separating headers from signed-headers list
        signed_headers,
        &x_content_sha256,
    ]
    .join("\n");

    // --- Step 3: Build String to Sign --------------------------------------
    let credential_scope = format!("{short_x_date}/{region}/{service}/request");

    let hashed_canonical = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = [
        "HMAC-SHA256",
        &x_date,
        &credential_scope,
        &hashed_canonical,
    ]
    .join("\n");

    // --- Step 4: Derive signing key and calculate signature ----------------
    let signing_key = derive_signing_key(SECRET_KEY, short_x_date, region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, &string_to_sign));

    // --- Step 5: Build Authorization header --------------------------------
    let authorization = format!(
        "HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        ACCESS_KEY, credential_scope, signed_headers, signature,
    );

    // --- Step 6: Build and send the HTTP request ---------------------------
    let url = format!("https://{endpoint}/?{sorted_query}");

    let client = reqwest::blocking::Client::new();

    let request_builder = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        _ => return Err(format!("unsupported HTTP method: {method}").into()),
    };

    let request_builder = if is_get {
        request_builder
    } else {
        request_builder.body(body.to_string())
    };

    let response = request_builder
        .header("Host", endpoint)
        .header("X-Date", &x_date)
        .header("X-Content-Sha256", &x_content_sha256)
        .header("Content-Type", content_type)
        .header("Authorization", &authorization)
        .send()?;

    let status = response.status();
    let response_body = response.text()?;

    println!("Status: {status}");
    println!("Response: {response_body}");

    Ok(response_body)
}

// ============================================================
// Main — three example API calls
// ============================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ----------------------------------------------------------------
    // Example 1: POST JSON — ListCoupons (billing service)
    // ----------------------------------------------------------------
    println!("=== Example 1: POST Json Request - ListCoupons ===");
    do_request(
        "POST",
        "open.volcengineapi.com",
        "cn-beijing",
        "billing",
        &[
            ("Action", "ListCoupons"),
            ("Version", "2022-01-01"),
        ],
        r#"{"Limit":1}"#,
        "application/json",
    )?;
    println!();

    // ----------------------------------------------------------------
    // Example 2: GET — ListUsers (iam service)
    // ----------------------------------------------------------------
    println!("=== Example 2: GET Request - ListUsers ===");
    do_request(
        "GET",
        "open.volcengineapi.com",
        "cn-beijing",
        "iam",
        &[
            ("Action", "ListUsers"),
            ("Version", "2018-01-01"),
            ("Limit", "1"),
        ],
        "{}",
        "application/json",
    )?;
    println!();

    // ----------------------------------------------------------------
    // Example 3: POST Form — DescribeImages (ecs service)
    // ----------------------------------------------------------------
    println!("=== Example 3: POST Form Request - DescribeImages ===");
    do_request(
        "POST",
        "open.volcengineapi.com",
        "cn-beijing",
        "ecs",
        &[
            ("Action", "DescribeImages"),
            ("Version", "2020-04-01"),
        ],
        "OsType=Linux&MaxResults=1",
        "application/x-www-form-urlencoded",
    )?;

    Ok(())
}
