#!/usr/bin/env perl

# Copyright (year) Beijing Volcano Engine Technology Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;

use Digest::SHA qw(sha256_hex hmac_sha256);
use HTTP::Tiny;
use POSIX qw(strftime);
use URI::Escape qw(uri_escape);

# ==========================================
# Configuration
# ==========================================

my $ACCESS_KEY_ID     = "YOUR AK";
my $SECRET_ACCESS_KEY = "YOUR SK";
my $ENDPOINT          = "open.volcengineapi.com";
my $API_PATH          = "/";
my $REGION            = "cn-beijing";
my $SCHEMA            = "https";

# ==========================================
# Helper Functions
# ==========================================

# RFC 3986 URL encoding: unreserved characters are A-Za-z0-9-_.~
sub url_encode {
    my ($str) = @_;
    return uri_escape($str, "^A-Za-z0-9\\-_.~");
}

# SHA256 hex digest of a string
sub hash_sha256 {
    my ($data) = @_;
    return sha256_hex($data);
}

# HMAC-SHA256 returning raw bytes
sub hmac_sha256_raw {
    my ($key, $data) = @_;
    return hmac_sha256($data, $key);
}

# Build sorted query string from a list of key-value pairs
# Input: array ref of [key, value] pairs
# Output: URL-encoded query string sorted by key
sub build_sorted_query_string {
    my ($params) = @_;
    my @encoded;
    for my $pair (@$params) {
        my ($k, $v) = @$pair;
        push @encoded, url_encode($k) . "=" . url_encode($v);
    }
    my @sorted = sort @encoded;
    return join("&", @sorted);
}

# Derive the signing key using HMAC-SHA256 chain
sub derive_signing_key {
    my ($secret_key, $date, $region, $service) = @_;
    my $k_date    = hmac_sha256_raw($secret_key,  $date);
    my $k_region  = hmac_sha256_raw($k_date,      $region);
    my $k_service = hmac_sha256_raw($k_region,     $service);
    my $k_signing = hmac_sha256_raw($k_service,    "request");
    return $k_signing;
}

# ==========================================
# Main Request Function
# ==========================================

sub do_request {
    my (%args) = @_;

    my $method       = $args{method};
    my $service      = $args{service};
    my $content_type = $args{content_type};
    my $body         = $args{body};
    my $query_params = $args{query_params};  # array ref of [key, value]

    my $is_get = ($method eq "GET");
    my $body_for_sign = $is_get ? "" : $body;

    # Step 1: Prepare date and content hash
    my $x_date           = strftime("%Y%m%dT%H%M%SZ", gmtime());
    my $short_x_date     = substr($x_date, 0, 8);
    my $x_content_sha256 = hash_sha256($body_for_sign);
    my $signed_headers   = "content-type;host;x-content-sha256;x-date";

    # Step 2: Build canonical request
    my $sorted_query_string = build_sorted_query_string($query_params);

    my $canonical_request = join("\n",
        $method,
        $API_PATH,
        $sorted_query_string,
        "content-type:" . $content_type,
        "host:" . $ENDPOINT,
        "x-content-sha256:" . $x_content_sha256,
        "x-date:" . $x_date,
        "",
        $signed_headers,
        $x_content_sha256,
    );

    # Step 3: Build string to sign
    my $credential_scope = join("/", $short_x_date, $REGION, $service, "request");
    my $hashed_canonical = hash_sha256($canonical_request);

    my $string_to_sign = join("\n",
        "HMAC-SHA256",
        $x_date,
        $credential_scope,
        $hashed_canonical,
    );

    # Step 4: Derive signing key
    my $signing_key = derive_signing_key($SECRET_ACCESS_KEY, $short_x_date, $REGION, $service);

    # Step 5: Calculate signature
    my $signature = unpack("H*", hmac_sha256_raw($signing_key, $string_to_sign));

    # Step 6: Build Authorization header
    my $authorization = sprintf(
        "HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        $ACCESS_KEY_ID,
        $credential_scope,
        $signed_headers,
        $signature,
    );

    # Step 7: Send HTTP request
    my $url = sprintf("%s://%s%s?%s", $SCHEMA, $ENDPOINT, $API_PATH, $sorted_query_string);

    my $http = HTTP::Tiny->new();
    my $response;

    my %headers = (
        "X-Date"           => $x_date,
        "X-Content-Sha256" => $x_content_sha256,
        "Content-Type"     => $content_type,
        "Authorization"    => $authorization,
    );

    my %request_opts = (headers => \%headers);
    if (!$is_get) {
        $request_opts{content} = $body;
    }
    $response = $http->request($method, $url, \%request_opts);

    return $response->{content};
}

# ==========================================
# Example 1: POST Json Request - ListCoupons (billing service)
# ==========================================

print "=== Example 1: POST Json Request - ListCoupons ===\n";

my $resp1 = do_request(
    method       => "POST",
    service      => "billing",
    content_type => "application/json",
    body         => '{"Limit":1}',
    query_params => [
        ["Action",  "ListCoupons"],
        ["Version", "2022-01-01"],
    ],
);
print $resp1 . "\n\n";

# ==========================================
# Example 2: GET Request - ListUsers (iam service)
# ==========================================

print "=== Example 2: GET Request - ListUsers ===\n";

my $resp2 = do_request(
    method       => "GET",
    service      => "iam",
    content_type => "application/json",
    body         => "{}",
    query_params => [
        ["Action",  "ListUsers"],
        ["Version", "2018-01-01"],
        ["Limit",   "1"],
    ],
);
print $resp2 . "\n\n";

# ==========================================
# Example 3: POST Form Request - DescribeImages (ecs service)
# ==========================================

print "=== Example 3: POST Form Request - DescribeImages ===\n";

my $resp3 = do_request(
    method       => "POST",
    service      => "ecs",
    content_type => "application/x-www-form-urlencoded",
    body         => "OsType=Linux&MaxResults=1",
    query_params => [
        ["Action",  "DescribeImages"],
        ["Version", "2020-04-01"],
    ],
);
print $resp3 . "\n\n";
