# frozen_string_literal: true

# Inspired from ../python/sign.py

require 'time'
require 'openssl'
require 'cgi'
require 'net/http'
require 'uri'
require 'json'

# 以下参数视服务不同而不同，一个服务内通常是一致的
SERVICE = 'ark'
VERSION = '2024-01-01'
REGION = 'cn-beijing'
HOST = 'open.volcengineapi.com'
CONTENT_TYPE = 'application/json'
ACTION = 'GetApiKey'
ENDPOINT = '<YOUR_ENDPOINT>'

# 请求的凭证，从IAM或者STS服务中获取
AK = '<YOUR_ACCESS_KEY>'
SK = '<YOUR_SECRET_KEY>'

def norm_query(params)
  query = params.sort.map do |key, value|
    if value.is_a?(Array)
      value.map { |v| "#{CGI.escape(key.to_s)}=#{CGI.escape(v.to_s)}" }.join('&')
    else
      "#{CGI.escape(key.to_s)}=#{CGI.escape(value.to_s)}"
    end
  end.join('&')
  query.gsub('+', '%20')
end

# sha256 非对称加密
def hmac_sha256(key, content)
  OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, content)
end

# sha256 hash算法
def hash_sha256(content)
  Digest::SHA256.hexdigest(content)
end

def request(method, query, header, body)
  credential = {
    'access_key_id' => AK,
    'secret_access_key' => SK,
    'service' => SERVICE,
    'region' => REGION
  }

  request_param = {
    'body' => body || '',
    'host' => HOST,
    'path' => '/',
    'method' => method,
    'content_type' => CONTENT_TYPE,
    'date' => Time.now.utc,
    'query' => { 'Action' => ACTION, 'Version' => VERSION }.merge(query)
  }

  x_date = request_param['date'].utc.strftime('%Y%m%dT%H%M%SZ')
  short_x_date = x_date[0, 8]
  x_content_sha256 = hash_sha256(request_param['body'])

  sign_result = {
    'Host' => request_param['host'],
    'X-Content-Sha256' => x_content_sha256,
    'X-Date' => x_date
  }

  signed_headers_str = 'host;x-content-sha256;x-date'
  canonical_request_str = [
    request_param['method'].upcase,
    request_param['path'],
    norm_query(request_param['query']),
    "host:#{request_param['host']}",
    "x-content-sha256:#{x_content_sha256}",
    "x-date:#{x_date}",
    '',
    signed_headers_str,
    x_content_sha256
  ].join("\n")

  puts canonical_request_str
  hashed_canonical_request = hash_sha256(canonical_request_str)
  puts hashed_canonical_request

  credential_scope = [short_x_date, credential['region'], credential['service'], 'request'].join('/')
  string_to_sign = ['HMAC-SHA256', x_date, credential_scope, hashed_canonical_request].join("\n")
  puts string_to_sign

  k_date = hmac_sha256(credential['secret_access_key'], short_x_date)
  k_region = hmac_sha256(k_date, credential['region'])
  k_service = hmac_sha256(k_region, credential['service'])
  k_signing = hmac_sha256(k_service, 'request')
  signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), k_signing, string_to_sign)
  puts signature

  sign_result['Authorization'] = "HMAC-SHA256 Credential=#{credential['access_key_id']}/#{credential_scope}, SignedHeaders=#{signed_headers_str}, Signature=#{signature}"

  puts sign_result

  header.merge!(sign_result)

  uri = URI.parse("https://#{request_param['host']}#{request_param['path']}")
  uri.query = URI.encode_www_form(request_param['query'])

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = if method.upcase == 'GET'
              Net::HTTP::Get.new(uri.request_uri, header)
            else
              Net::HTTP::Post.new(uri, header).tap do |req|
                req.body = request_param['body']
                req.content_type = CONTENT_TYPE
              end
            end
  response = http.request(request)
  JSON.parse(response.body)
end

body =
  '{
    "DurationSeconds": 2592000,
    "ResourceType": "endpoint",
    "ResourceIds": [
        "' + ENDPOINT + '"
    ]
}'

response = request 'POST', {}, {}, body
print "\n#{response}"

