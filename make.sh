#!/usr/bin/env bash

cargo build
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

mkdir -p node1

cp target/debug/peerwave node1/peerwave
