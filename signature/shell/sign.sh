#!/bin/bash

# Copyright (year) Beijing Volcano Engine Technology Ltd.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# ==========================================
# Environment detection and tool check
# ==========================================

# Detect operating system
OS="$(uname -s)"
case "${OS}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${OS}"
esac

# Define required tools list
REQUIRED_TOOLS=("openssl" "curl" "sed" "xxd" "date")
MISSING_TOOLS=()

# Check if tools exist
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

# If tools are missing, print error and exit
if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "Error: The following required tools are missing:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    
    echo ""
    if [ "$machine" == "Mac" ]; then
        echo "Suggestion: You can install missing tools using Homebrew (e.g., 'brew install <tool_name>')."
        echo "Note: 'xxd' is often part of 'vim' or provided separately."
    elif [ "$machine" == "Linux" ]; then
        echo "Suggestion: Please install them using your package manager."
        echo "  - Debian/Ubuntu: apt-get install <package_name>"
        echo "  - CentOS/RHEL: yum install <package_name>"
        echo "Note: 'xxd' is often part of the 'vim-common' package."
    fi
    exit 1
fi

# ==========================================
# Request Logic
# ==========================================

# Configuration info
ACCESS_KEY_ID="YOUR AK"
SECRET_ACCESS_KEY="YOUR SK"
ENDPOINT="open.volcengineapi.com"
API_PATH="/"
REGION="cn-beijing"
SCHEMA="https"

# Request parameter configuration

# URL encoding function
url_encode() {
    local string="$1"
    local strlen=${#string}
    local encoded=""
    local pos=0
    local c o

    while [ "$pos" -lt "$strlen" ]; do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9])
                o="${c}"
                ;;
            ' ')
                o="%20"
                ;;
            *)
                o=$(printf '%%%02X' "'$c")
                ;;
        esac
        encoded="${encoded}${o}"
        pos=$((pos + 1))
    done
    echo "${encoded}"
}

# SHA256 hash function
hash_sha256() {
    printf %s "$1" | openssl dgst -sha256 -hex | sed 's/.* //'
}

# HMAC-SHA256 function (hex output, supports normal key and hex key)
hmac_sha256_hex() {
    local key_option="$1" # "key:..." or "hexkey:..."
    local data="$2"
    printf %s "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key_option" | sed 's/.* //'
}

# Generate signing key
gen_signing_key() {
    local secret_key="$1"
    local date="$2"
    local region="$3"
    local service="$4"
    
    local k_date=$(hmac_sha256_hex "key:${secret_key}" "$date")
    local k_region=$(hmac_sha256_hex "hexkey:${k_date}" "$region")
    local k_service=$(hmac_sha256_hex "hexkey:${k_region}" "$service")
    local k_signing=$(hmac_sha256_hex "hexkey:${k_service}" "request")
    
    echo "$k_signing"
}

# Main function
do_request() {
    # 1. Prepare parameters
    local body="$BODY"
    local content_type="$CONTENT_TYPE"
    local x_content_sha256=$(hash_sha256 "$body")
    
    # Timestamp
    local x_date=$(date -u +"%Y%m%dT%H%M%SZ")
    local short_x_date=${x_date:0:8}
    
    local sign_header="content-type;host;x-content-sha256;x-date"
    
    # 2. Process query parameters (Use globally defined QUERY_PARAMS array)
    # Construct encoded k=v array
    declare -a encoded_args
    for (( i=0; i<${#QUERY_PARAMS[@]}; i+=2 )); do
        key=${QUERY_PARAMS[i]}
        val=${QUERY_PARAMS[i+1]}
        encoded_key=$(url_encode "$key")
        encoded_val=$(url_encode "$val")
        encoded_args+=("${encoded_key}=${encoded_val}")
    done
    
    # Sort
    IFS=$'\n' sorted_args=($(sort <<<"${encoded_args[*]}"))
    unset IFS
    
    # Join query string
    local query_string=$(IFS='&'; echo "${sorted_args[*]}")
    
    # Construct canonical request
    local canonical_request="${METHOD}
${API_PATH}
${query_string}
content-type:${content_type}
host:${ENDPOINT}
x-content-sha256:${x_content_sha256}
x-date:${x_date}

${sign_header}
${x_content_sha256}"
    
    # Calculate hash of canonical request
    local hashed_canonical_request=$(hash_sha256 "$canonical_request")
    
    # Construct string to sign
    local credential_scope="${short_x_date}/${REGION}/${SERVICE}/request"
    local string_to_sign="HMAC-SHA256
${x_date}
${credential_scope}
${hashed_canonical_request}"
    
    # Generate signing key
    local signing_key=$(gen_signing_key "$SECRET_ACCESS_KEY" "$short_x_date" "$REGION" "$SERVICE")
    
    # Calculate signature
    # Calculate signature
    local signature=$(hmac_sha256_hex "hexkey:$signing_key" "$string_to_sign")
    
    # Construct authorization header
    local authorization="HMAC-SHA256 Credential=${ACCESS_KEY_ID}/${credential_scope}, SignedHeaders=${sign_header}, Signature=${signature}"
    
    # Send request
    local url="${SCHEMA}://${ENDPOINT}${API_PATH}?${query_string}"
    
    curl -s -X "$METHOD" "$url" \
        -H "Host: ${ENDPOINT}" \
        -H "X-Date: ${x_date}" \
        -H "X-Content-Sha256: ${x_content_sha256}" \
        -H "Content-Type: ${content_type}" \
        -H "Authorization: ${authorization}" \
        -d "$body" 
}

# --------------------------------------------------------------------------------
# Example 1: POST Json Request - ListCoupons (billing service)
# --------------------------------------------------------------------------------
echo "=== Example 1: POST Json Request - ListCoupons ==="
SERVICE="billing"
METHOD="POST"
VERSION="2022-01-01"
CONTENT_TYPE="application/json"
BODY="{\"Limit\":1}"

declare -a QUERY_PARAMS=()
QUERY_PARAMS+=("Action" "ListCoupons")
QUERY_PARAMS+=("Version" "$VERSION")

do_request
echo ""

# --------------------------------------------------------------------------------
# Example 2: GET Request - ListUsers (iam service)
# --------------------------------------------------------------------------------
echo "=== Example 2: GET Request - ListUsers ==="
SERVICE="iam"
METHOD="GET"
VERSION="2018-01-01"
CONTENT_TYPE="application/json"
BODY="{}"

declare -a QUERY_PARAMS=()
QUERY_PARAMS+=("Action" "ListUsers")
QUERY_PARAMS+=("Version" "$VERSION")
QUERY_PARAMS+=("Limit" "1")

do_request
echo ""

# --------------------------------------------------------------------------------
# Example 3: POST Form Request - DescribeImages (ecs service)
# --------------------------------------------------------------------------------
echo "=== Example 3: POST Form Request - DescribeImages ==="
SERVICE="ecs"
METHOD="POST"
VERSION="2020-04-01"
CONTENT_TYPE="application/x-www-form-urlencoded"
BODY="OsType=Linux&MaxResults=1"

declare -a QUERY_PARAMS=()
QUERY_PARAMS+=("Action" "DescribeImages")
QUERY_PARAMS+=("Version" "$VERSION")

do_request
echo ""
