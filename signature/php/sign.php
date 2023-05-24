<?php
/**
 * Copyright (year) Beijing Volcano Engine Technology Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require 'vendor/autoload.php';

// 需要自行安装 composer（https://getcomposer.org/doc/00-intro.md），并安装GuzzleHttp依赖， composer require guzzlehttp/guzzle:^7.0
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;


$Service = "iam";
$Version = "2018-01-01";
$Region = "cn-north-1";
$Host = "iam.volcengineapi.com";
$ContentType = "application/x-www-form-urlencoded";
/**
 * @throws GuzzleException
 */
// 第一步：创建一个  API 请求函数。签名计算的过程包含在该函数中。
function request($method, $query, $header, $ak, $sk, $action, $body)
{

    // 第二步：创建身份证明。其中的 Service 和 Region 字段是固定的。ak 和 sk 分别代表
    // AccessKeyID 和 SecretAccessKey。同时需要初始化签名结构体。一些签名计算时需要的属性也在这里处理。
    // 初始化身份证明结构体
    global $Service, $Region, $Host, $Version, $ContentType;
    $credential = [
        'accessKeyId' => $ak,
        'secretKeyId' => $sk,
        'service' => $Service,
        'region' => $Region,
    ];

    // 初始化签名结构体
    $requestParam = [
        // body是http请求需要的原生body
        'body' => $body,
        'host' => $Host,
        'path' => '/',
        'method' => $method,
        'contentType' => $ContentType,
        'date' => gmdate('Ymd\THis\Z'),
        'query' => ksort(array_merge($query, [
            'Action' => $action,
            'Version' => $Version
        ]))
    ];

    // 第三步：接下来开始计算签名。在计算签名前，先准备好用于接收签算结果的 signResult 变量，并设置一些参数。
    // 初始化签名结果的结构体
    $xDate = $requestParam['date'];
    $shortXDate = substr($xDate, 0, 8);
    $xContentSha256 = hash('sha256', $requestParam['body']);
    $signResult = [
        'Host' => $requestParam['host'],
        'X-Content-Sha256' => $xContentSha256,
        'X-Date' => $xDate,
        'Content-Type' => $requestParam['contentType']
    ];
    // 第四步：计算 Signature 签名。
    $signedHeaderStr = join(';', ['content-type', 'host', 'x-content-sha256', 'x-date']);
    $canonicalRequestStr = join("\n", [
        $requestParam['method'],
        $requestParam['path'],
        http_build_query($requestParam['query']),
        join("\n", ['content-type:' . $requestParam['contentType'], 'host:' . $requestParam['host'], 'x-content-sha256:' . $xContentSha256, 'x-date:' . $xDate]),
        '',
        $signedHeaderStr,
        $xContentSha256
    ]);
    $hashedCanonicalRequest = hash("sha256", $canonicalRequestStr);
    $credentialScope = join('/', [$shortXDate, $credential['region'], $credential['service'], 'request']);
    $stringToSign = join("\n", ['HMAC-SHA256', $xDate, $credentialScope, $hashedCanonicalRequest]);
    $kDate = hash_hmac("sha256", $shortXDate, $credential['secretKeyId'], true);
    $kRegion = hash_hmac("sha256", $credential['region'], $kDate, true);
    $kService = hash_hmac("sha256", $credential['service'], $kRegion, true);
    $kSigning = hash_hmac("sha256", 'request', $kService, true);
    $signature = hash_hmac("sha256", $stringToSign, $kSigning);
    $signResult['Authorization'] = sprintf("HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s", $credential['accessKeyId'] . '/' . $credentialScope, $signedHeaderStr, $signature);
    $header = array_merge($header, $signResult);
    // 第五步：将 Signature 签名写入 HTTP Header 中，并发送 HTTP 请求。
    $client = new Client([
        'base_uri' => 'https://' . $requestParam['host'],
        'timeout' => 120.0,
    ]);
    return $client->request($method, 'https://' . $requestParam['host'] . $requestParam['path'], [
        'headers' => $header,
        'query' => $requestParam['query'],
        'body' => $requestParam['body']
    ]);
}

$now = time();

$requestBody ="";

$AK = 'ak';
$SK = 'sk';

try {
    $response = request("GET", [], [], $AK, $SK, "ListUsers", $requestBody);
    print_r($response->getBody()->getContents());
} catch (GuzzleException $e) {
    print_r($e->getMessage());
}