#!/bin/fish

cmake .
make
./echo_server -c www.example.com,./certs/server.cert,./certs/server.key -s 127.0.0.3:8989

