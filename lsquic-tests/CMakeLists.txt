# Copyright (c) 2017 - 2021 LiteSpeed Technologies Inc.  See LICENSE.

cmake_minimum_required(VERSION 3.17)
project(lsquic_tests C)

set(CMAKE_C_STANDARD 99)

IF(CMAKE_BUILD_TYPE STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
IF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
ELSEIF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
ENDIF()
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

ADD_SUBDIRECTORY(boringssl)

INCLUDE_DIRECTORIES(boringssl/include)
INCLUDE_DIRECTORIES(lsquic/include)
INCLUDE_DIRECTORIES(lsquic/src/liblsquic)       # For lsquic_xxhash.h
ADD_SUBDIRECTORY(lsquic/src/liblsquic)


ADD_EXECUTABLE(echo_server echo_server.c prog.c test_common.c test_cert.c)
ADD_EXECUTABLE(echo_client echo_client.c prog.c test_common.c test_cert.c)

SET(LIBS lsquic crypto ssl z m event)
TARGET_LINK_LIBRARIES(echo_server ${LIBS})
TARGET_LINK_LIBRARIES(echo_client ${LIBS})

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(sendmmsg HAVE_SENDMMSG)
CHECK_FUNCTION_EXISTS(recvmmsg HAVE_RECVMMSG)
CHECK_FUNCTION_EXISTS(open_memstream HAVE_OPEN_MEMSTREAM)

INCLUDE(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(
        IP_MTU_DISCOVER
        "netinet/in.h"
        HAVE_IP_MTU_DISCOVER
)

CHECK_SYMBOL_EXISTS(
        IP_DONTFRAG
        "netinet/in.h"
        HAVE_IP_DONTFRAG
)

CHECK_SYMBOL_EXISTS(
        preadv
        "sys/uio.h"
        HAVE_PREADV
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/test_config.h)
