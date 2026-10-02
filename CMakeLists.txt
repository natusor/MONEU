cmake_minimum_required(VERSION 3.16)
project(moneu VERSION 0.2.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE   "-O2 -DNDEBUG")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -Wextra")

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
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va")
else()
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now")
endif()

option(STATIC_DEPS "Build the dependencies into the binaries" OFF)

if(STATIC_DEPS)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(Boost_USE_STATIC_LIBS ON)
    set(OPENSSL_USE_STATIC_LIBS ON)
    set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
endif()

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -DNOGDI -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost 1.74 REQUIRED COMPONENTS
    filesystem
    system
    thread
    program_options
)

set(LEVELDB_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(HAVE_SNAPPY OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LEVELDB_INSTALL          OFF CACHE BOOL "" FORCE)

set(LEVELDB_SAVED_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
set(LEVELDB_SAVED_C_FLAGS   "${CMAKE_C_FLAGS}")
string(REPLACE "-Wall" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "-Wextra" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "-Wall" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REPLACE "-Wextra" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

add_subdirectory(src/leveldb EXCLUDE_FROM_ALL)

set(CMAKE_CXX_FLAGS "${LEVELDB_SAVED_CXX_FLAGS}")
set(CMAKE_C_FLAGS   "${LEVELDB_SAVED_C_FLAGS}")

set(LEVELDB_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/src/leveldb/include)
set(LEVELDB_LIBRARY leveldb)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${LEVELDB_INCLUDE_DIR}
)

add_subdirectory(src)
