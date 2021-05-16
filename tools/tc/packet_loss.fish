#!/bin/fish

set INT eno1 
set DPORT 4433
set MASK 0xffff
set LOSS 10%

tc qdisc add    \
    dev $INT    \
    root        \
    handle 1:0  \
    prio

tc filter add                           \
    dev $INT                            \
    protocol ip                         \
    parent 1:0                          \
    prio 1                              \
    u32 match ip dport $DPORT $MASK     \
    class 1:1

tc qdisc add    \
    dev $INT    \
    parent 1:1  \
    handle 10:0 \
    netem loss \
    $LOSS

