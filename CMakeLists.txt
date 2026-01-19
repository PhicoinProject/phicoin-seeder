cmake_minimum_required(VERSION 3.15)
project(ravencoin_seeder)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

find_package(OpenSSL REQUIRED)

add_executable(ravencoin_seeder
        phicoin.cpp
        phicoin.h
        combine.pl
        compat.h
        db.cpp
        db.h
        dns.cpp
        dns.h
        main.cpp
        Makefile
        netbase.cpp
        netbase.h
        protocol.cpp
        protocol.h
        README
        serialize.h
        strlcpy.h
        test.pl
        uint256.h
        util.cpp
        util.h)

target_link_libraries(ravencoin_seeder OpenSSL::Crypto)
