#!/bin/sh

./configure \
  --prefix=/usr \
  --localstatedir=/var/run/frr \
  --sbindir=/usr/lib/frr \
  --sysconfdir=/etc/frr \
  --enable-vtysh \
  --enable-pimd \
  --enable-sharpd \
  --enable-multipath=64 \
  --enable-user=frr \
  --enable-group=frr \
  --enable-vty-group=frrvty \
  --enable-address-sanitizer \
  --with-pkg-extra-version=-play-imifumei-behavior-with-asan

#--enable-address-sanitizer
#--with-pkg-extra-version=-play-imifumei-behavior-without-asan
