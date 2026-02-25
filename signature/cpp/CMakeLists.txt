cmake_minimum_required(VERSION 3.10)
project(volc_sign_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(sign_demo sign.cpp)

target_include_directories(sign_demo PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(sign_demo PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)
