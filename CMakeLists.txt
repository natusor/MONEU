cmake_minimum_required(VERSION 3.16)
project(moneu VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# No -DDEBUG here. LogLevel has an enumerator named DEBUG, and defining a
# macro of that name turns the enumerator into a numeric constant, which
# stops the Debug configuration compiling at all - and with it every
# sanitizer run.
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE   "-O2 -DNDEBUG")

# Warnings apply to the C half as well. sha2.c, base58.c, ripemd160.c and
# the key derivation code are compiled as C, and building them without any
# warning flags meant a future edit could introduce one unseen.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -Wextra")

# Hardening for a daemon that parses input from strangers.
include(CheckCXXCompilerFlag)
foreach(flag -fstack-protector-strong -fno-strict-aliasing)
    string(REPLACE "-" "_" flagvar ${flag})
    check_cxx_compiler_flag(${flag} HAS${flagvar})
    if(HAS${flagvar})
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
        set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${flag}")
    endif()
endforeach()
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-D_FORTIFY_SOURCE=2)
endif()
set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS
    filesystem
    system
    thread
    program_options
)

find_path(LEVELDB_INCLUDE_DIR leveldb/db.h)
find_library(LEVELDB_LIBRARY leveldb)
if(NOT LEVELDB_INCLUDE_DIR OR NOT LEVELDB_LIBRARY)
    message(FATAL_ERROR "LevelDB not found!")
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${LEVELDB_INCLUDE_DIR}
)

add_subdirectory(src)
