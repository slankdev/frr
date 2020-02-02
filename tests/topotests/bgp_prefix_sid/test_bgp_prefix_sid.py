#!/usr/bin/env python

#
# test_bgp_prefix_sid.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by LINE Corporation
# Copyright (c) 2020 by Hiroki Shirokura <slank.dev@gmail.com>
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

"""
test_bgp_prefix_sid.py: Test BGP topology with EBGP on prefix-sid
"""

import json
import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, **_opts):
        tgen = get_topogen(self)
        router = tgen.add_router('r1')
        switch = tgen.add_switch('s1')
        switch.add_link(router)

        switch = tgen.gears['s1']
        peer1 = tgen.add_exabgp_peer('peer1', ip='10.0.1.101', defaultRoute='via 10.0.1.1')
        peer2 = tgen.add_exabgp_peer('peer2', ip='10.0.1.102', defaultRoute='via 10.0.1.1')
        switch.add_link(peer1)
        switch.add_link(peer2)


def setup_module(module):
    tgen = Topogen(TemplateTopo, module.__name__)
    tgen.start_topology()

    router = tgen.gears['r1']
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, '{}/zebra.conf'.format('r1')))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, '{}/bgpd.conf'.format('r1')))
    router.start()

    logger.info('starting exaBGP on peer1')
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.iteritems():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, 'exabgp.env')
        logger.info('Running ExaBGP peer')
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_r1_receive_prefix_sid_type4():
    tgen = get_topogen()
    router = tgen.gears['r1']

    def _check_type4_r1(router):
        output = router.vtysh_cmd('show bgp ipv4 vpn rd 1:1 4.4.4.4/32 json')
        output = json.loads(output)
        expected = {
            '1:1': {
                'prefix': '4.4.4.4/32',
                'paths': [ { 'valid':True, 'remoteSid': '2001:0:0:1:40::' } ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type4_r1, router)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type4_r1 in "{}"'.format(router)


def test_r1_receive_prefix_sid_type5():
    tgen = get_topogen()
    router = tgen.gears['r1']

    def _check_type5_r1(router):
        output = router.vtysh_cmd('show bgp ipv4 vpn rd 1:1 5.5.5.5/32 json')
        output = json.loads(output)
        expected = {
            '1:1': {
                'prefix': '5.5.5.5/32',
                'paths': [ { 'valid':True, 'remoteSid': '2001:2::10' } ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type5_r1, router)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type5_r1 in "{}"'.format(router)


def exabgp_get_update_prefix(filename, afi, neighbor, prefix):
    with open('/tmp/peer2-received.log') as f:
        for line in f.readlines():
            output = json.loads(line)
            if output.get('neighbor').get('message').get('update').get('announce').get(afi).get(neighbor).get(prefix) is None:
                continue
            return output
        return "Not found"


def test_peer2_receive_prefix_sid_type4():
    tgen = get_topogen()
    peer2 = tgen.gears['peer2']

    def _check_type4_peer2():
        output = exabgp_get_update_prefix('/tmp/peer2-received.log', 'ipv4 mpls-vpn', '10.0.1.1', '4.4.4.4/32')
        if output is None:
            return "Not found"
        expected = {
            'type': 'update',
            'neighbor': {
                'ip': '10.0.1.1',
                'message': {
                    'update': {
                        'attribute': {
                            'attribute-0x28-0xE0': '0x04001300010020010000000000010040000000000000'
                        },
                        'announce': {
                            'ipv4 mpls-vpn': {
                                '10.0.1.1': {
                                    '4.4.4.4/32': { 'route-distinguisher': '1:1' }
                                }
                            }
                        }
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type4_peer2)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type4_peer2 in "{}"'.format('peer2')


def test_peer2_receive_prefix_sid_type5():
    tgen = get_topogen()
    peer2 = tgen.gears['peer2']

    def _check_type5_peer2():
        output = exabgp_get_update_prefix('/tmp/peer2-received.log', 'ipv4 mpls-vpn', '10.0.1.1', '5.5.5.5/32')
        if output is None:
            return "Not found"
        expected = {
            'type': 'update',
            'neighbor': {
                'ip': '10.0.1.1',
                'message': {
                    'update': {
                        'attribute': {
                            'attribute-0x28-0xE0': '0x050015002001000200000000000000000000001000ffff00'
                        },
                        'announce': {
                            'ipv4 mpls-vpn': {
                                '10.0.1.1': {
                                    '5.5.5.5/32': { 'route-distinguisher': '1:1' }
                                }
                            }
                        }
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type5_peer2)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type5_peer2 in "{}"'.format('peer2')


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)
    sys.exit(ret)
