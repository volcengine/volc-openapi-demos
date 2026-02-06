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

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

// --------------------------------------------------------------------------------
// Example 1: GET Request - ListUsers (iam service)
// --------------------------------------------------------------------------------
var iamSign = new Sign(region: "cn-beijing",
    service: "iam",
    schema: "https",
    host: "open.volcengineapi.com",
    path: "/",
    ak: "Your AK",
    sk: "Your SK"
);

var resp1 = iamSign.Request(
    method: HttpMethod.Get,
    queryList: new List<KeyValuePair<string, string>>()
    {
        new KeyValuePair<string, string>("Limit", "1")
    },
    body: Array.Empty<byte>(),
    contentType: "application/x-www-form-urlencoded",
    date: DateTimeOffset.UtcNow,
    action: "ListUsers",
    version: "2018-01-01"
);
Console.WriteLine(resp1);
Console.WriteLine(Encoding.UTF8.GetString(ReadFully(resp1.Content.ReadAsStream())));

// --------------------------------------------------------------------------------
// Example 2: POST Json Request - CVSync2AsyncSubmitTask (cv service)
// --------------------------------------------------------------------------------
var cvSign = new Sign(region: "cn-beijing",
    service: "cv",
    schema: "https",
    host: "open.volcengineapi.com",
    path: "/",
    ak: "Your AK",
    sk: "Your SK"
);

var resp2 = cvSign.Request(
    method: HttpMethod.Post,
    queryList: new List<KeyValuePair<string, string>>(),
    body: Encoding.UTF8.GetBytes("{\"force_single\":false,\"max_ratio\":3,\"min_ratio\":0.33,\"prompt\":\"生成一张天空的图片\",\"req_key\":\"jimeng_t2i_v40\",\"scale\":0.5,\"size\":4194304}"),
    contentType: "application/json",
    date: DateTimeOffset.UtcNow,
    action: "CVSync2AsyncSubmitTask",
    version: "2022-08-31"
);

Console.WriteLine(resp2);
Console.WriteLine(Encoding.UTF8.GetString(ReadFully(resp2.Content.ReadAsStream())));

// --------------------------------------------------------------------------------
// Example 3: POST Form Request - DescribeImages (ecs service)
// --------------------------------------------------------------------------------
var ecsSign = new Sign(region: "cn-beijing",
    service: "ecs",
    schema: "https",
    host: "open.volcengineapi.com",
    path: "/",
    ak: "Your AK",
    sk: "Your SK"
);

var resp3 = ecsSign.Request(
    method: HttpMethod.Post,
    queryList: new List<KeyValuePair<string, string>>(),
    body: Encoding.UTF8.GetBytes("OsType=Linux&MaxResults=1"),
    contentType: "application/x-www-form-urlencoded",
    date: DateTimeOffset.UtcNow,
    action: "DescribeImages",
    version: "2020-04-01"
);

Console.WriteLine(resp3);
Console.WriteLine(Encoding.UTF8.GetString(ReadFully(resp3.Content.ReadAsStream())));


static byte[] ReadFully(Stream? input)
{
    if (input == null)
    {
        return Array.Empty<byte>();
    }

    using (MemoryStream ms = new MemoryStream())
    {
        input.CopyTo(ms);
        return ms.ToArray();
    }
}

class Sign
{
    private readonly string _region;
    private readonly string _service;
    private readonly string _schema;
    private readonly string _host;
    private readonly string _path;
    private readonly string _ak;
    private readonly string _sk;

    private static readonly Encoding Utf8 = Encoding.UTF8;

    private readonly HttpClient _httpClient;

    public Sign(string region, string service, string schema, string host, string path, string ak, string sk)
    {
        _region = region;
        _service = service;
        _schema = schema;
        _host = host;
        _path = path;
        _ak = ak;
        _sk = sk;
        _httpClient = new HttpClient();
    }

    public HttpResponseMessage Request(HttpMethod method, List<KeyValuePair<string, string>> queryList,
        byte[]? body, string contentType,
        DateTimeOffset date, string action, string version)
    {
        body ??= Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(contentType))
        {
            contentType = "application/x-www-form-urlencoded";
        }

        string xContentSha256 = ToHexString(HashSha256(body));
        string xDate = date.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'");
        string shortXDate = xDate[..8];
        string signHeader = "content-type;host;x-content-sha256;x-date";

        var realQueryList = new NameValueCollection();
        queryList.ForEach(s => realQueryList.Add(s.Key, s.Value));
        realQueryList.Add("Action", action);
        realQueryList.Add("Version", version);

        var query = string.Join("&", realQueryList.AllKeys.ToImmutableSortedSet().Select(key =>
        {
            var values = realQueryList.GetValues(key)?.ToImmutableSortedSet() ?? ImmutableSortedSet<string>.Empty;
            return string.Join("&",
                values.Select(value => $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}"));
        }));
        string canonicalStringBuilder =
            $"{method}\n" +
            $"{_path}\n" +
            $"{query}\n" +
            $"content-type:{contentType}\n" +
            $"host:{_host}\n" +
            $"x-content-sha256:{xContentSha256}\n" +
            $"x-date:{xDate}\n" +
            $"\n" +
            $"{signHeader}\n" +
            $"{xContentSha256}";

        string hashCanonicalString = ToHexString(HashSha256(Utf8.GetBytes(canonicalStringBuilder)));
        string credentialScope = $"{shortXDate}/{_region}/{_service}/request";
        string signString = $"HMAC-SHA256\n{xDate}\n{credentialScope}\n{hashCanonicalString}";

        byte[] signKey = GenSigningSecretKeyV4(_sk, shortXDate, _region, _service);
        string signature = ToHexString(HmacSha256(signKey, signString));

        Uri url = new Uri($"{_schema}://{_host}{_path}?{query}");
        var request = new HttpRequestMessage();
        request.Method = method;
        request.RequestUri = url;
        request.Headers.TryAddWithoutValidation("Host", _host);
        request.Headers.Add("X-Date", xDate);
        request.Headers.Add("X-Content-Sha256", xContentSha256);
        request.Headers.TryAddWithoutValidation("Authorization",
            $"HMAC-SHA256 Credential={_ak}/{credentialScope}, SignedHeaders={signHeader}, Signature={signature}");
        HttpContent content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        request.Content = content;

        return _httpClient.Send(request);
    }

    private byte[] GenSigningSecretKeyV4(string secretKey, string date, string region, string service)
    {
        byte[] kDate = HmacSha256(Utf8.GetBytes(secretKey), date);
        byte[] kRegion = HmacSha256(kDate, region);
        byte[] kService = HmacSha256(kRegion, service);
        return HmacSha256(kService, "request");
    }

    private static byte[] HmacSha256(byte[] secret, string text)
    {
        using HMACSHA256 mac = new HMACSHA256(secret);
        var hash = mac.ComputeHash(Encoding.UTF8.GetBytes(text));
        return hash;
    }

    private static byte[] HashSha256(byte[] data)
    {
        using SHA256 sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        return hash;
    }

    private static string ToHexString(byte[]? bytes)
    {
        if (bytes == null)
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        foreach (var t in bytes)
        {
            sb.Append(t.ToString("X2"));
        }

        return sb.ToString().ToLower();
    }
}
