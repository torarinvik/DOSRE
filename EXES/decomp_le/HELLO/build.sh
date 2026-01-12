#!/usr/bin/env sh
set -e
cc -std=c99 -O0 -g -o blst main.c bdata.c b[0-9]*.c
echo "Built ./blst"
