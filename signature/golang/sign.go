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
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	// 请求凭证，从访问控制申请
	AccessKeyID     = "AK****"
	SecretAccessKey = "****"

	// 请求地址
	Addr = "https://iam.volcengineapi.com"
	Path = "/" // 路径，不包含 Query

	// 请求接口信息
	Service = "iam"
	Region  = "cn-beijing"
	Action  = "ListPolicies"
	Version = "2018-01-01"
)

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func getSignedKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte(secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "request")

	return kSigning
}

func hashSHA256(data []byte) []byte {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		log.Printf("input hash err:%s", err.Error())
	}

	return hash.Sum(nil)
}

func doRequest(method string, queries url.Values, body []byte) error {
	// 1. 构建请求
	queries.Set("Action", Action)
	queries.Set("Version", Version)
	requestAddr := fmt.Sprintf("%s%s?%s", Addr, Path, queries.Encode())
	log.Printf("request addr: %s\n", requestAddr)

	request, err := http.NewRequest(method, requestAddr, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("bad request: %w", err)
	}

	// 2. 构建签名材料
	now := time.Now()
	date := now.UTC().Format("20060102T150405Z")
	authDate := date[:8]
	request.Header.Set("X-Date", date)

	payload := hex.EncodeToString(hashSHA256(body))
	request.Header.Set("X-Content-Sha256", payload)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	queryString := strings.Replace(queries.Encode(), "+", "%20", -1)
	signedHeaders := []string{"host", "x-date", "x-content-sha256", "content-type"}
	var headerList []string
	for _, header := range signedHeaders {
		if header == "host" {
			headerList = append(headerList, header+":"+request.Host)
		} else {
			v := request.Header.Get(header)
			headerList = append(headerList, header+":"+strings.TrimSpace(v))
		}
	}
	headerString := strings.Join(headerList, "\n")

	canonicalString := strings.Join([]string{
		method,
		Path,
		queryString,
		headerString + "\n",
		strings.Join(signedHeaders, ";"),
		payload,
	}, "\n")
	log.Printf("canonical string:\n%s\n", canonicalString)

	hashedCanonicalString := hex.EncodeToString(hashSHA256([]byte(canonicalString)))
	log.Printf("hashed canonical string: %s\n", hashedCanonicalString)

	credentialScope := authDate + "/" + Region + "/" + Service + "/request"
	signString := strings.Join([]string{
		"HMAC-SHA256",
		date,
		credentialScope,
		hashedCanonicalString,
	}, "\n")
	log.Printf("sign string:\n%s\n", signString)

	// 3. 构建认证请求头
	signedKey := getSignedKey(SecretAccessKey, authDate, Region, Service)
	signature := hex.EncodeToString(hmacSHA256(signedKey, signString))
	log.Printf("signature: %s\n", signature)

	authorization := "HMAC-SHA256" +
		" Credential=" + AccessKeyID + "/" + credentialScope +
		", SignedHeaders=" + strings.Join(signedHeaders, ";") +
		", Signature=" + signature
	request.Header.Set("Authorization", authorization)
	log.Printf("authorization: %s\n", authorization)

	// 4. 打印请求，发起请求
	requestRaw, err := httputil.DumpRequest(request, true)
	if err != nil {
		return fmt.Errorf("dump request err: %w", err)
	}

	log.Printf("request:\n%s\n", string(requestRaw))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("do request err: %w", err)
	}

	// 5. 打印响应
	responseRaw, err := httputil.DumpResponse(response, true)
	if err != nil {
		return fmt.Errorf("dump response err: %w", err)
	}

	log.Printf("response:\n%s\n", string(responseRaw))

	if response.StatusCode == 200 {
		log.Printf("请求成功")
	} else {
		log.Printf("请求失败")
	}

	return nil
}

func main() {
	// GET 请求例子
	query1 := make(url.Values)
	query1.Set("Limit", "1")
	query1.Set("Scope", "Custom")
	doRequest(http.MethodGet, query1, nil)

	// Post 请求例子
	// query2 := make(url.Values)
	// query2.Set("Limit", "1")
	// jsonBody := map[string]string{
	// 	"req_key": "jimeng_t2i_v40",
	// 	"prompt":  "a photo of a cat",
	// }
	// bodyBytes, _ := json.Marshal(jsonBody)
	// doRequest(http.MethodPost, query2, bodyBytes)

}
