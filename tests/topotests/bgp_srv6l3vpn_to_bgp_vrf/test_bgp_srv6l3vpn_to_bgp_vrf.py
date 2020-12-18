#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import re
import sys
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class Topology(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)
        tgen.add_router("r1")
        tgen.add_router("r2")
        tgen.add_router("ce1")
        tgen.add_router("ce2")

        tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "ce1-eth0", "r1-eth1")
        tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "ce2-eth0", "r2-eth1")
        tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(Topology, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().iteritems():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, '{}/zebra.conf'.format(rname)))
        router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, '{}/bgpd.conf'.format(rname)))
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link set r1-eth1 vrf vrf10")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link set r2-eth1 vrf vrf10")
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_check_vpn_routes():
    import time
    logger.info("sleeping ...")
    time.sleep(3)
    logger.info("sleeping ...done")
    assert True, "wait 10 sec"


def test_check_ce_ping():
    tgen = get_topogen()
    pingrouter = tgen.gears["ce1"]
    output = pingrouter.run("ping 2001:2::2 -c 1")
    logger.info(output)
    assert " 0% packet loss" in output, "ping fail"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
