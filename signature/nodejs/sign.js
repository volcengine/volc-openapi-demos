"use strict";
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
const crypto = require("crypto");
const util = require("util");
const url = require("url");
const fetch = require("node-fetch");
const qs = require("querystring");
const debuglog = util.debuglog('signer');


/**
 * 不参与加签过程的 header key
 */
const HEADER_KEYS_TO_IGNORE = new Set([
    "authorization",
    "content-type",
    "content-length",
    "user-agent",
    "presigned-expires",
    "expect",
]);

// do request example
async function doRequest() {
    const signParams = {
        headers: {
            // x-date header 是必传的
            ["X-Date"]: getDateTimeNow(),
        },
        method: 'GET',
        query: {
            Version: '2018-01-01',
            Action: 'ListPolicies',
        },
        accessKeyId: '*******',
        secretAccessKey: '**********',
        serviceName: 'iam',
        region: 'cn-beijing',
    };
    // 正规化 query object， 防止串化后出现 query 值为 undefined 情况
    for (const [key, val] of Object.entries(signParams.query)) {
        if (val === undefined || val === null) {
            signParams.query[key] = '';
        }
    }
    const authorization = sign(signParams);
    const res = await fetch(`https://iam.volcengineapi.com/?${qs.stringify(signParams.query)}`, {
        headers: {
            ...signParams.headers,
            'Authorization': authorization,
        },
        method: signParams.method,
    });
    const responseText = await res.text();
    console.log(responseText);
}

doRequest();


function sign(params) {
    const {
        headers = {},
        query = {},
        region = '',
        serviceName = '',
        method = '',
        pathName = '/',
        accessKeyId = '',
        secretAccessKey = '',
        needSignHeaderKeys = [],
        bodySha,
    } = params;
    const datetime = headers["X-Date"];
    const date = datetime.substring(0, 8); // YYYYMMDD
    // 创建正规化请求
    const [signedHeaders, canonicalHeaders] = getSignHeaders(headers, needSignHeaderKeys);
    const canonicalRequest = [
        method.toUpperCase(),
        pathName,
        queryParamsToString(query) || '',
        `${canonicalHeaders}\n`,
        signedHeaders,
        bodySha || hash(''),
    ].join('\n');
    const credentialScope = [date, region, serviceName, "request"].join('/');
    // 创建签名字符串
    const stringToSign = ["HMAC-SHA256", datetime, credentialScope, hash(canonicalRequest)].join('\n');
    // 计算签名
    const kDate = hmac(secretAccessKey, date);
    const kRegion = hmac(kDate, region);
    const kService = hmac(kRegion, serviceName);
    const kSigning = hmac(kService, "request");
    const signature = hmac(kSigning, stringToSign).toString('hex');
    debuglog('--------CanonicalString:\n%s\n--------SignString:\n%s', canonicalRequest, stringToSign);

    return [
        "HMAC-SHA256",
        `Credential=${accessKeyId}/${credentialScope},`,
        `SignedHeaders=${signedHeaders},`,
        `Signature=${signature}`,
    ].join(' ');
}

function hmac(secret, s) {
    return crypto.createHmac('sha256', secret).update(s, 'utf8').digest();
}

function hash(s) {
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function queryParamsToString(params) {
    return Object.keys(params)
        .sort()
        .map((key) => {
            const val = params[key];
            if (typeof val === 'undefined' || val === null) {
                return undefined;
            }
            const escapedKey = uriEscape(key);
            if (!escapedKey) {
                return undefined;
            }
            if (Array.isArray(val)) {
                return `${escapedKey}=${val.map(uriEscape).sort().join(`&${escapedKey}=`)}`;
            }
            return `${escapedKey}=${uriEscape(val)}`;
        })
        .filter((v) => v)
        .join('&');
}

function getSignHeaders(originHeaders, needSignHeaders) {
    function trimHeaderValue(header) {
        return header.toString?.().trim().replace(/\s+/g, ' ') ?? '';
    }

    let h = Object.keys(originHeaders);
    // 根据 needSignHeaders 过滤
    if (Array.isArray(needSignHeaders)) {
        const needSignSet = new Set([...needSignHeaders, 'x-date', 'host'].map((k) => k.toLowerCase()));
        h = h.filter((k) => needSignSet.has(k.toLowerCase()));
    }
    // 根据 ignore headers 过滤
    h = h.filter((k) => !HEADER_KEYS_TO_IGNORE.has(k.toLowerCase()));
    const signedHeaderKeys = h
        .slice()
        .map((k) => k.toLowerCase())
        .sort()
        .join(';');
    const canonicalHeaders = h
        .sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1))
        .map((k) => `${k.toLowerCase()}:${trimHeaderValue(originHeaders[k])}`)
        .join('\n');
    return [signedHeaderKeys, canonicalHeaders];
}

function uriEscape(str) {
    try {
        return encodeURIComponent(str)
            .replace(/[^A-Za-z0-9_.~\-%]+/g, escape)
            .replace(/[*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
    } catch (e) {
        return '';
    }
}

function getDateTimeNow() {
    const now = new Date();
    return now.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

// 获取 body sha256
function getBodySha(body) {
    const hash = crypto.createHash('sha256');
    if (typeof body === 'string') {
        hash.update(body);
    } else if (body instanceof url.URLSearchParams) {
        hash.update(body.toString());
    } else if (util.isBuffer(body)) {
        hash.update(body);
    }
    return hash.digest('hex');
}
