#!/usr/bin/env python

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd
from mininet.topo import Topo


class ThisTestTopo(Topo):
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Generate Nodes
        for routern in range(1, 3):
            tgen.add_router('r{}'.format(routern))
        for routern in range(1, 5):
            tgen.add_router('c{}'.format(routern))

        # Generate Links
        tgen.add_link(tgen.gears['r1'], tgen.gears['r2'], 'r1-eth0', 'r2-eth0')
        tgen.add_link(tgen.gears['r1'], tgen.gears['c1'], 'r1-eth1', 'c1-eth0')
        tgen.add_link(tgen.gears['r1'], tgen.gears['c2'], 'r1-eth2', 'c2-eth0')
        tgen.add_link(tgen.gears['r2'], tgen.gears['c3'], 'r2-eth1', 'c3-eth0')
        tgen.add_link(tgen.gears['r2'], tgen.gears['c4'], 'r2-eth2', 'c4-eth0')


def ltemplatePreRouterStartHook():
    logger.info('pre router-start hook')
    cc = ltemplateRtrCmd()
    tgen = get_topogen()

    # Configure r1 Nodes
    cc.doCmd(tgen, 'r1', 'ip link add vrf1 type vrf table 1')
    cc.doCmd(tgen, 'r1', 'ip link add vrf2 type vrf table 2')
    cc.doCmd(tgen, 'r1', 'ip link set vrf1 up')
    cc.doCmd(tgen, 'r1', 'ip link set vrf2 up')
    cc.doCmd(tgen, 'r1', 'ip link set r1-eth1 vrf vrf1')
    cc.doCmd(tgen, 'r1', 'ip link set r1-eth2 vrf vrf2')
    cc.doCmd(tgen, 'r1', 'sysctl -w net.ipv6.conf.all.forwarding=1')
    cc.doCmd(tgen, 'r1', 'ip link set r1-eth0 down')
    cc.doCmd(tgen, 'r1', 'ip link set r1-eth0 address 52:54:00:11:00:00')
    cc.doCmd(tgen, 'r1', 'ip link set r1-eth0 up')

    # Configure r1 Nodes
    cc.doCmd(tgen, 'r2', 'ip link add vrf1 type vrf table 1')
    cc.doCmd(tgen, 'r2', 'ip link add vrf2 type vrf table 2')
    cc.doCmd(tgen, 'r2', 'ip link set vrf1 up')
    cc.doCmd(tgen, 'r2', 'ip link set vrf2 up')
    cc.doCmd(tgen, 'r2', 'ip link set r2-eth1 vrf vrf1')
    cc.doCmd(tgen, 'r2', 'ip link set r2-eth2 vrf vrf2')
    cc.doCmd(tgen, 'r2', 'sysctl -w net.ipv6.conf.all.forwarding=1')
    cc.doCmd(tgen, 'r2', 'ip link set r2-eth0 down')
    cc.doCmd(tgen, 'r2', 'ip link set r2-eth0 address 52:54:00:22:00:00')
    cc.doCmd(tgen, 'r2', 'ip link set r2-eth0 up')

    return True


def ltemplatePostRouterStartHook():
    logger.info('post router-start hook')
    return True
