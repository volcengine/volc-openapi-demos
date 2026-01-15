/**
 * 火山引擎 HMAC-SHA256 签名示例 (TypeScript / Node.js fetch)
 * 经过了测试，请求成功
 */

import crypto from "crypto";
import querystring from "querystring";

const ACCESS_KEY_ID = ""; // 从访问控制申请
const SECRET_ACCESS_KEY = "==";

const ADDR = "https://visual.volcengineapi.com";
const PATH = "/"; // 请求路径
const SERVICE = "cv";
const REGION = "cn-north-1";
const ACTION = "CVSync2AsyncSubmitTask";
const VERSION = "2022-08-31";

function hmacSHA256(key: Buffer | string, content: string): Buffer {
  return crypto.createHmac("sha256", key).update(content).digest();
}

function getSignedKey(secretKey: string, date: string, region: string, service: string): Buffer {
  const kDate = hmacSHA256(Buffer.from(secretKey, "utf-8"), date);
  const kRegion = hmacSHA256(kDate, region);
  const kService = hmacSHA256(kRegion, service);
  const kSigning = hmacSHA256(kService, "request");
  return kSigning;
}

function hashSHA256(data: Buffer | string): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

async function doRequest(method: "GET" | "POST", queries: Record<string, string>, body: object | null) {
  // ====== 1. 构建请求 ======
  queries["Action"] = ACTION;
  queries["Version"] = VERSION;
  const queryString = querystring.stringify(queries, "&", "=").replace(/\+/g, "%20");
  const requestAddr = `${ADDR}${PATH}?${queryString}`;

  const bodyBuffer = body ? Buffer.from(JSON.stringify(body), "utf-8") : Buffer.alloc(0);

  // ====== 2. 构建签名材料 ======
  const now = new Date();
  const isoDate = now.toISOString(); // 2024-06-27T15:04:05.000Z
  const date = isoDate.replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z"); // 20240627T150405Z
  const authDate = date.substring(0, 8);

  const payload = hashSHA256(bodyBuffer).toString("hex");

  // 签名 header 列表
  const host = new URL(ADDR).host;
  const signedHeaders = ["host", "x-date", "x-content-sha256", "content-type"];
  const headerList = [`host:${host}`, `x-date:${date}`, `x-content-sha256:${payload}`, `content-type:application/json`];

  const headerString = headerList.join("\n");

  const canonicalString = [method, PATH, queryString, headerString + "\n", signedHeaders.join(";"), payload].join("\n");

  const hashedCanonicalString = hashSHA256(canonicalString).toString("hex");

  const credentialScope = `${authDate}/${REGION}/${SERVICE}/request`;
  const signString = ["HMAC-SHA256", date, credentialScope, hashedCanonicalString].join("\n");

  // ====== 3. 计算签名 ======
  const signedKey = getSignedKey(SECRET_ACCESS_KEY, authDate, REGION, SERVICE);
  const signature = hmacSHA256(signedKey, signString).toString("hex");

  const authorization =
    `HMAC-SHA256 Credential=${ACCESS_KEY_ID}/${credentialScope}, ` + `SignedHeaders=${signedHeaders.join(";")}, Signature=${signature}`;

  // ====== 4. 发起请求 ======
  const headers: Record<string, string> = {
    Host: host,
    "X-Date": date,
    "X-Content-Sha256": payload,
    "Content-Type": "application/json",
    Authorization: authorization,
  };

  console.log("===== 请求信息 =====");
  console.log("URL:", requestAddr);
  console.log("Method:", method);
  console.log("Headers:", headers);
  if (body) console.log("Body:", JSON.stringify(body));

  const res = await fetch(requestAddr, {
    method,
    headers,
    body: method === "POST" ? bodyBuffer : undefined,
  });

  const text = await res.text();
  console.log("===== 响应信息 =====");
  console.log("Status:", res.status);
  console.log("Body:", text);

  if (res.status === 200) {
    console.log("请求成功");
  } else {
    console.log("请求失败");
  }
}

// 入口
(async () => {
  const body = {
    req_key: "jimeng_t2i_v40",
    prompt: "a photo of a cat",
  };

  await doRequest("POST", {}, body);

  // GET 请求示例
  // await doRequest("GET", { Limit: "1", Scope: "Custom" }, null);
})();
