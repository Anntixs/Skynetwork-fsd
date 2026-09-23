cmake_minimum_required(VERSION 3.16)
project(Skynetwork-fsd CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_library(skynet_common STATIC src/accounts.cpp src/net.cpp)
target_include_directories(skynet_common PUBLIC src)
target_link_libraries(skynet_common PUBLIC OpenSSL::Crypto SQLite::SQLite3)

add_executable(skynet-fsd src/main.cpp src/fsd_server.cpp)
target_link_libraries(skynet-fsd PRIVATE skynet_common)

add_executable(skynet-admin src/admin.cpp)
target_link_libraries(skynet-admin PRIVATE skynet_common)
