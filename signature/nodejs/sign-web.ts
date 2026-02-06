// 火山引擎 HMAC-SHA256 签名示例（浏览器版）

const ACCESS_KEY_ID = ""; // 从访问控制申请
const SECRET_ACCESS_KEY = "==";

const ADDR = "https://visual.volcengineapi.com";
const PATH = "/"; // 请求路径
const SERVICE = "cv";
const REGION = "cn-north-1";
const ACTION = "CVSync2AsyncSubmitTask";
const VERSION = "2022-08-31";

const encoder = new TextEncoder();

// ArrayBuffer -> hex 字符串
function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const hex: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    hex.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return hex.join("");
}

// 浏览器版 HMAC-SHA256
async function hmacSHA256(key: string | ArrayBuffer, content: string): Promise<ArrayBuffer> {
  const keyBytes = typeof key === "string" ? encoder.encode(key) : new Uint8Array(key);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(content));
  return sig; // ArrayBuffer
}

// 浏览器版 SHA256
async function hashSHA256(data: string | ArrayBuffer): Promise<ArrayBuffer> {
  const bytes = typeof data === "string" ? encoder.encode(data) : new Uint8Array(data);
  return crypto.subtle.digest("SHA-256", bytes);
}

// 派生签名 key：kDate -> kRegion -> kService -> kSigning
async function getSignedKey(secretKey: string, date: string, region: string, service: string): Promise<ArrayBuffer> {
  const kDate = await hmacSHA256(secretKey, date);
  const kRegion = await hmacSHA256(kDate, region);
  const kService = await hmacSHA256(kRegion, service);
  const kSigning = await hmacSHA256(kService, "request");
  return kSigning;
}

async function doRequest(method: "GET" | "POST", queries: Record<string, string>, body: object | null): Promise<void> {
  // ====== 1. 构建请求 ======
  const q: Record<string, string> = { ...queries };
  q["Action"] = ACTION;
  q["Version"] = VERSION;

  // 用 URLSearchParams 模拟 querystring.stringify，并保持 + -> %20 的行为
  const usp = new URLSearchParams();
  Object.entries(q).forEach(([k, v]) => usp.append(k, v));
  const queryString = usp.toString().replace(/\+/g, "%20");
  const requestAddr = `${ADDR}${PATH}?${queryString}`;

  const bodyString = body ? JSON.stringify(body) : "";

  // ====== 2. 构建签名材料 ======
  const now = new Date();
  const isoDate = now.toISOString(); // 2024-06-27T15:04:05.000Z
  const date = isoDate.replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z"); // 20240627T150405Z
  const authDate = date.substring(0, 8);

  const payloadBuf = await hashSHA256(bodyString);
  const payload = arrayBufferToHex(payloadBuf);

  const host = new URL(ADDR).host;

  // 注意：浏览器里实际发送的 Host 头由浏览器自动加，fetch 里设置 "Host" 会被忽略。
  const signedHeaders = ["host", "x-date", "x-content-sha256", "content-type"];
  const headerList = [`host:${host}`, `x-date:${date}`, `x-content-sha256:${payload}`, `content-type:application/json`];
  const headerString = headerList.join("\n");

  const canonicalString = [method, PATH, queryString, headerString + "\n", signedHeaders.join(";"), payload].join("\n");

  const hashedCanonical = await hashSHA256(canonicalString);
  const hashedCanonicalHex = arrayBufferToHex(hashedCanonical);

  const credentialScope = `${authDate}/${REGION}/${SERVICE}/request`;
  const signString = ["HMAC-SHA256", date, credentialScope, hashedCanonicalHex].join("\n");

  // ====== 3. 计算签名 ======
  const signedKey = await getSignedKey(SECRET_ACCESS_KEY, authDate, REGION, SERVICE);
  const signatureBuf = await hmacSHA256(signedKey, signString);
  const signature = arrayBufferToHex(signatureBuf);

  const authorization =
    `HMAC-SHA256 Credential=${ACCESS_KEY_ID}/${credentialScope}, ` + `SignedHeaders=${signedHeaders.join(";")}, Signature=${signature}`;

  // ====== 4. 发起请求 ======
  const headers: Record<string, string> = {
    // Host 头浏览器会自动带上，这里不用设置
    "X-Date": date,
    "X-Content-Sha256": payload,
    "Content-Type": "application/json",
    Authorization: authorization,
  };

  console.log("===== 请求信息 =====");
  console.log("URL:", requestAddr);
  console.log("Method:", method);
  console.log("Headers:", headers);
  if (body) console.log("Body:", bodyString);

  const res = await fetch(requestAddr, {
    method,
    headers,
    body: method === "POST" ? bodyString : undefined,
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

// ====== 浏览器入口示例 ======
(async () => {
  const body = {
    req_key: "jimeng_t2i_v40",
    prompt: "a photo of a cat",
  };

  await doRequest("POST", {}, body);

  // GET 请求示例
  // await doRequest("GET", { Limit: "1", Scope: "Custom" }, null);
})();
