#!/bin/fish

cmake .
make
./echo_client -o ql_bits=2 -G . -H www.example.com -s 127.0.0.3:8989

