#!/bin/sh
set -xue

DIR=../../../
make -C $DIR -j8
make -C $DIR -j8 install
./test_route_scale.py
