#!/bin/bash



gcc -I/home/thien-nam/Code/tor/src/or \
    -I/home/thien-nam/Code/tor/src/common \
    -I/home/thien-nam/Code/tor/src/win32 \
    -I/home/thien-nam/Code/tor/src/config \
    -I/home/thien-nam/Code/tor/src/rust \
    -I/home/thien-nam/Code/tor/src/test \
    -I/home/thien-nam/Code/tor/src/tools \
    -I/home/thien-nam/Code/tor/src/trace \
    -I/home/thien-nam/Code/tor/src/trunnel \
    -I/home/thien-nam/Code/tor/src/ext \
    -I/home/thien-nam/Code/tor/src/ext/keccak-tiny \
    test_mt_main.c test_mt_crypto.c test_mt_tokens.c test_mt_common.c test_mt_lpay.c ../mt_tokens.c ../mt_common.c ../mt_crypto.c ../mt_lpay.c -o test_mt_main `pkg-config --cflags --libs glib-2.0` -lssl -lcrypto -Wall  && test_mt_main
