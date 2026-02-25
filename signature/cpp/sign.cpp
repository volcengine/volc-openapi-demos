/*
Copyright (year) Beijing Volcano Engine Technology Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <curl/curl.h>

// ============================================================================
// Configuration
// ============================================================================

static const std::string ACCESS_KEY_ID     = "YOUR AK";
static const std::string SECRET_ACCESS_KEY = "YOUR SK";
static const std::string ENDPOINT          = "open.volcengineapi.com";
static const std::string REGION            = "cn-beijing";
static const std::string SCHEMA            = "https";
static const std::string API_PATH          = "/";

// ============================================================================
// Helper: convert raw bytes to lowercase hex string
// ============================================================================
static std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

// ============================================================================
// SHA-256 hash, returns lowercase hex string
// ============================================================================
static std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()),
           input.size(), hash);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

// ============================================================================
// HMAC-SHA256, returns raw binary bytes in a std::string
// ============================================================================
static std::string hmac_sha256_raw(const std::string& key,
                                   const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(),
         result, &result_len);
    return std::string(reinterpret_cast<char*>(result), result_len);
}

// ============================================================================
// HMAC-SHA256, returns lowercase hex string
// ============================================================================
static std::string hmac_sha256_hex(const std::string& key,
                                   const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(),
         result, &result_len);
    return to_hex(result, result_len);
}

// ============================================================================
// RFC 3986 percent-encoding (unreserved: A-Za-z0-9 - _ . ~)
// ============================================================================
static std::string url_encode(const std::string& value) {
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(value[i]);
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << static_cast<char>(c);
        } else {
            encoded << '%' << std::setw(2)
                    << static_cast<unsigned int>(c);
        }
    }
    return encoded.str();
}

// ============================================================================
// Get current UTC time formatted as YYYYMMDDTHHMMSSZ
// ============================================================================
static std::string utc_now_formatted() {
    std::time_t now = std::time(NULL);
    struct tm utc_tm;
#if defined(_WIN32)
    gmtime_s(&utc_tm, &now);
#else
    gmtime_r(&now, &utc_tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &utc_tm);
    return std::string(buf);
}

// ============================================================================
// libcurl write callback: appends received data to a std::string
// ============================================================================
static size_t write_callback(char* ptr, size_t size, size_t nmemb,
                             void* userdata) {
    size_t total = size * nmemb;
    std::string* response = static_cast<std::string*>(userdata);
    response->append(ptr, total);
    return total;
}

// ============================================================================
// Build sorted, encoded query string from key-value pairs
// ============================================================================
static std::string build_query_string(
        const std::vector<std::pair<std::string, std::string> >& params) {
    // Encode each key and value, then sort by encoded key
    std::vector<std::pair<std::string, std::string> > encoded;
    encoded.reserve(params.size());
    for (size_t i = 0; i < params.size(); ++i) {
        encoded.push_back(std::make_pair(
            url_encode(params[i].first),
            url_encode(params[i].second)));
    }
    std::sort(encoded.begin(), encoded.end());

    std::ostringstream oss;
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (i > 0) oss << '&';
        oss << encoded[i].first << '=' << encoded[i].second;
    }
    return oss.str();
}

// ============================================================================
// Derive signing key using HMAC-SHA256 chain
// ============================================================================
static std::string derive_signing_key(const std::string& secret_key,
                                      const std::string& date,
                                      const std::string& region,
                                      const std::string& service) {
    std::string k_date    = hmac_sha256_raw(secret_key, date);
    std::string k_region  = hmac_sha256_raw(k_date, region);
    std::string k_service = hmac_sha256_raw(k_region, service);
    std::string k_signing = hmac_sha256_raw(k_service, "request");
    return k_signing;
}

// ============================================================================
// Perform a signed request to Volcano Engine OpenAPI
// ============================================================================
static void do_request(
        const std::string& service,
        const std::string& method,
        const std::string& content_type,
        const std::string& body,
        const std::vector<std::pair<std::string, std::string> >& query_params) {

    // 1. Prepare signing materials
    const bool is_get = (method == "GET");
    const std::string body_for_sign = is_get ? std::string() : body;
    std::string x_date           = utc_now_formatted();
    std::string short_x_date     = x_date.substr(0, 8);
    std::string x_content_sha256 = sha256_hex(body_for_sign);
    std::string signed_headers   = "content-type;host;x-content-sha256;x-date";

    // 2. Build sorted query string
    std::string query_string = build_query_string(query_params);

    // 3. Build canonical request
    std::string canonical_request =
        method + "\n" +
        API_PATH + "\n" +
        query_string + "\n" +
        "content-type:" + content_type + "\n" +
        "host:" + ENDPOINT + "\n" +
        "x-content-sha256:" + x_content_sha256 + "\n" +
        "x-date:" + x_date + "\n" +
        "\n" +
        signed_headers + "\n" +
        x_content_sha256;

    // 4. Build string to sign
    std::string credential_scope = short_x_date + "/" + REGION + "/" +
                                   service + "/request";
    std::string hashed_canonical = sha256_hex(canonical_request);
    std::string string_to_sign =
        "HMAC-SHA256\n" +
        x_date + "\n" +
        credential_scope + "\n" +
        hashed_canonical;

    // 5. Derive signing key and compute signature
    std::string signing_key = derive_signing_key(SECRET_ACCESS_KEY,
                                                 short_x_date,
                                                 REGION, service);
    std::string signature = hmac_sha256_hex(signing_key, string_to_sign);

    // 6. Build Authorization header
    std::string authorization =
        "HMAC-SHA256 Credential=" + ACCESS_KEY_ID + "/" + credential_scope +
        ", SignedHeaders=" + signed_headers +
        ", Signature=" + signature;

    // 7. Build full URL
    std::string url = SCHEMA + "://" + ENDPOINT + API_PATH + "?" + query_string;

    // 8. Send HTTP request via libcurl
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Error: failed to initialize libcurl" << std::endl;
        return;
    }

    std::string response_body;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers,
        ("Host: " + ENDPOINT).c_str());
    headers = curl_slist_append(headers,
        ("X-Date: " + x_date).c_str());
    headers = curl_slist_append(headers,
        ("X-Content-Sha256: " + x_content_sha256).c_str());
    headers = curl_slist_append(headers,
        ("Content-Type: " + content_type).c_str());
    headers = curl_slist_append(headers,
        ("Authorization: " + authorization).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    if (is_get) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(body.size()));
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "Error: curl request failed: "
                  << curl_easy_strerror(res) << std::endl;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        std::cout << "HTTP Status: " << http_code << std::endl;
        std::cout << "Response: " << response_body << std::endl;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// ============================================================================
// Main: run three API examples
// ============================================================================
int main() {
    curl_global_init(CURL_GLOBAL_ALL);

    // --------------------------------------------------------------------
    // Example 1: POST Json Request - ListCoupons (billing service)
    // --------------------------------------------------------------------
    std::cout << "=== Example 1: POST Json Request - ListCoupons ==="
              << std::endl;
    {
        std::vector<std::pair<std::string, std::string> > params;
        params.push_back(std::make_pair("Action",  "ListCoupons"));
        params.push_back(std::make_pair("Version", "2022-01-01"));

        do_request("billing",                   // service
                   "POST",                      // method
                   "application/json",          // content-type
                   "{\"Limit\":1}",             // body
                   params);                     // query params
    }
    std::cout << std::endl;

    // --------------------------------------------------------------------
    // Example 2: GET Request - ListUsers (iam service)
    // --------------------------------------------------------------------
    std::cout << "=== Example 2: GET Request - ListUsers ==="
              << std::endl;
    {
        std::vector<std::pair<std::string, std::string> > params;
        params.push_back(std::make_pair("Action",  "ListUsers"));
        params.push_back(std::make_pair("Version", "2018-01-01"));
        params.push_back(std::make_pair("Limit",   "1"));

        do_request("iam",                       // service
                   "GET",                       // method
                   "application/json",          // content-type
                   "{}",                        // body (matches shell demo)
                   params);                     // query params
    }
    std::cout << std::endl;

    // --------------------------------------------------------------------
    // Example 3: POST Form Request - DescribeImages (ecs service)
    // --------------------------------------------------------------------
    std::cout << "=== Example 3: POST Form Request - DescribeImages ==="
              << std::endl;
    {
        std::vector<std::pair<std::string, std::string> > params;
        params.push_back(std::make_pair("Action",  "DescribeImages"));
        params.push_back(std::make_pair("Version", "2020-04-01"));

        do_request("ecs",                                   // service
                   "POST",                                  // method
                   "application/x-www-form-urlencoded",     // content-type
                   "OsType=Linux&MaxResults=1",             // body
                   params);                                 // query params
    }
    std::cout << std::endl;

    curl_global_cleanup();
    return 0;
}
