#!/bin/fish

set INT eno1

tc qdisc delete dev $INT root
