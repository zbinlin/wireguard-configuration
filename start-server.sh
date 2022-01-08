#!/bin/sh

set -e

ADDRESS=192.168.128.1
export PORT=12345
export INTERFACE="wg0rand"

. ./server/prepare.sh

socat EXEC:./server/server.sh,pty,rawer TCP-LISTEN:${PORT},bind=${ADDRESS},fork,reuseaddr
