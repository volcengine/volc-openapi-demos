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

# Volcano Engine OpenAPI V4 Signature Demo (Ruby 2.6+)
# Uses only Ruby standard library - no external gems required.

require "openssl"
require "net/http"
require "uri"
require "json"
require "time"

# Configuration
ACCESS_KEY = "YOUR AK"
SECRET_KEY = "YOUR SK"

# RFC 3986 percent-encoding.
# Unreserved characters (A-Za-z0-9-_.~) are NOT encoded; everything else is %XX.
def uri_encode(str)
  str.to_s.each_byte.map { |byte|
    char = byte.chr
    if char =~ /[A-Za-z0-9\-_.~]/
      char
    else
      format("%%%02X", byte)
    end
  }.join
end

# SHA-256 hex digest of a string.
def sha256_hex(data)
  OpenSSL::Digest::SHA256.hexdigest(data)
end

# HMAC-SHA256 producing raw binary bytes.
def hmac_sha256(key, data)
  OpenSSL::HMAC.digest("SHA256", key, data)
end

# Derive the signing key by chaining HMAC-SHA256 operations.
#   kDate    = HMAC-SHA256(secret_key, date)
#   kRegion  = HMAC-SHA256(kDate, region)
#   kService = HMAC-SHA256(kRegion, service)
#   kSigning = HMAC-SHA256(kService, "request")
def derive_signing_key(secret_key, date, region, service)
  k_date    = hmac_sha256(secret_key, date)
  k_region  = hmac_sha256(k_date, region)
  k_service = hmac_sha256(k_region, service)
  hmac_sha256(k_service, "request")
end

# Build the V4 signature and send the HTTP request.
#
# Parameters (all keys are symbols):
#   :method       - "GET" or "POST"
#   :service      - e.g. "billing", "iam", "ecs"
#   :region       - e.g. "cn-beijing"
#   :endpoint     - e.g. "open.volcengineapi.com"
#   :ak           - Access Key ID
#   :sk           - Secret Access Key
#   :action       - API action, e.g. "ListCoupons"
#   :version      - API version, e.g. "2022-01-01"
#   :content_type - "application/json" or "application/x-www-form-urlencoded"
#   :body         - request body string
#   :query_params - array of [key, value] pairs for query string
#
# Returns the response body as a String.
def sign_and_request(params)
  method       = params[:method]
  service      = params[:service]
  region       = params[:region]
  endpoint     = params[:endpoint]
  ak           = params[:ak]
  sk           = params[:sk]
  content_type = params[:content_type]
  body         = params[:body]
  query_params = params[:query_params]
  path         = "/"
  is_get       = (method == "GET")
  body_for_sign = is_get ? "" : body

  # --- Step 1: Prepare signing materials ---
  now           = Time.now.utc
  x_date        = now.strftime("%Y%m%dT%H%M%SZ")
  short_x_date  = x_date[0, 8]
  x_content_sha256 = sha256_hex(body_for_sign)
  signed_headers   = "content-type;host;x-content-sha256;x-date"

  # --- Step 2: Build canonical query string ---
  # Encode each key and value with RFC 3986, then sort by encoded key.
  encoded_pairs = query_params.map { |k, v| [uri_encode(k), uri_encode(v)] }
  encoded_pairs.sort_by! { |pair| pair[0] }
  canonical_query_string = encoded_pairs.map { |k, v| "#{k}=#{v}" }.join("&")

  # --- Step 3: Build canonical request ---
  canonical_request = [
    method,
    path,
    canonical_query_string,
    "content-type:#{content_type}",
    "host:#{endpoint}",
    "x-content-sha256:#{x_content_sha256}",
    "x-date:#{x_date}",
    "",                  # empty line after headers
    signed_headers,
    x_content_sha256
  ].join("\n")

  # --- Step 4: Build string to sign ---
  credential_scope = "#{short_x_date}/#{region}/#{service}/request"
  hashed_canonical_request = sha256_hex(canonical_request)

  string_to_sign = [
    "HMAC-SHA256",
    x_date,
    credential_scope,
    hashed_canonical_request
  ].join("\n")

  # --- Step 5: Derive signing key and calculate signature ---
  signing_key = derive_signing_key(sk, short_x_date, region, service)
  signature   = OpenSSL::HMAC.hexdigest("SHA256", signing_key, string_to_sign)

  # --- Step 6: Build Authorization header ---
  authorization = "HMAC-SHA256 Credential=#{ak}/#{credential_scope}, " \
                  "SignedHeaders=#{signed_headers}, Signature=#{signature}"

  # --- Step 7: Send the HTTP request ---
  url = URI("https://#{endpoint}#{path}?#{canonical_query_string}")

  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true

  case method
  when "GET"
    request = Net::HTTP::Get.new(url)
  when "POST"
    request = Net::HTTP::Post.new(url)
  else
    raise ArgumentError, "Unsupported HTTP method: #{method}"
  end

  request["Host"]             = endpoint
  request["X-Date"]           = x_date
  request["X-Content-Sha256"] = x_content_sha256
  request["Content-Type"]     = content_type
  request["Authorization"]    = authorization
  request.body                = body unless is_get

  response = http.request(request)
  response.body
end

# ==============================================================================
# Examples
# ==============================================================================

# --- Example 1: POST JSON - ListCoupons (billing service) ---
puts "=== Example 1: POST Json Request - ListCoupons ==="
resp = sign_and_request(
  method:       "POST",
  service:      "billing",
  region:       "cn-beijing",
  endpoint:     "open.volcengineapi.com",
  ak:           ACCESS_KEY,
  sk:           SECRET_KEY,
  action:       "ListCoupons",
  version:      "2022-01-01",
  content_type: "application/json",
  body:         '{"Limit":1}',
  query_params: [["Action", "ListCoupons"], ["Version", "2022-01-01"]]
)
puts resp
puts

# --- Example 2: GET - ListUsers (iam service) ---
puts "=== Example 2: GET Request - ListUsers ==="
resp = sign_and_request(
  method:       "GET",
  service:      "iam",
  region:       "cn-beijing",
  endpoint:     "open.volcengineapi.com",
  ak:           ACCESS_KEY,
  sk:           SECRET_KEY,
  action:       "ListUsers",
  version:      "2018-01-01",
  content_type: "application/json",
  body:         "{}",
  query_params: [["Action", "ListUsers"], ["Version", "2018-01-01"], ["Limit", "1"]]
)
puts resp
puts

# --- Example 3: POST Form - DescribeImages (ecs service) ---
puts "=== Example 3: POST Form Request - DescribeImages ==="
resp = sign_and_request(
  method:       "POST",
  service:      "ecs",
  region:       "cn-beijing",
  endpoint:     "open.volcengineapi.com",
  ak:           ACCESS_KEY,
  sk:           SECRET_KEY,
  action:       "DescribeImages",
  version:      "2020-04-01",
  content_type: "application/x-www-form-urlencoded",
  body:         "OsType=Linux&MaxResults=1",
  query_params: [["Action", "DescribeImages"], ["Version", "2020-04-01"]]
)
puts resp
puts
