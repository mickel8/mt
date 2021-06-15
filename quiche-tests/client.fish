#!/bin/fish

QLOGDIR=/home/michal/Repos/mt/quiche-tests/ RUST_LOG=debug cargo run --bin client -- https://127.0.0.3:4433
