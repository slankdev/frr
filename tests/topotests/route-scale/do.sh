#!/bin/sh
set -xue

DIR=/root/git/frr
make -C $DIR -j8
make -C $DIR -j8 install

cd /root/git/frr/tests/topotests/route-scale/
./test_route_scale.py
