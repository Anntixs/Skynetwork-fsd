cmake_minimum_required(VERSION 3.16)
project(SkyNetwork CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_library(skynet_common STATIC common/accounts.cpp common/net.cpp)
target_include_directories(skynet_common PUBLIC common)
target_link_libraries(skynet_common PUBLIC OpenSSL::Crypto SQLite::SQLite3)

add_executable(skynet-fsd fsd/main.cpp fsd/fsd_server.cpp)
target_link_libraries(skynet-fsd PRIVATE skynet_common)

add_executable(skynet-voice voice/main.cpp voice/voice_server.cpp)
target_link_libraries(skynet-voice PRIVATE skynet_common)

add_executable(skynet-admin common/admin.cpp)
target_link_libraries(skynet-admin PRIVATE skynet_common)
