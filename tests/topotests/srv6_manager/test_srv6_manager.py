#!/usr/bin/env python

#
# test_srv6_manager.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# LINE Corporation, Hiroki Shirokura <slank.dev@gmail.com>
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
test_srv6_manager.py:
Test that SRv6 manager on zebra,staticd works fine.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo

class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)
        tgen.add_router('r1')

def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().iteritems():
        router.run("/bin/bash {}/setup".format(CWD))
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, '{}/zebra.conf'.format(rname)))
    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_srv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears['r1']

    def _srv6_locator(router):
        output = json.loads(router.vtysh_cmd("show segment-routing srv6 locator json"))
        expected = {
            "locators":[
                {
                    "name":"loc1",
                    "prefix":"2001:db8:1:1::/64"
                },
                {
                    "name":"loc2",
                    "prefix":"2001:db8:2:2::/64"
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_srv6_locator, router)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _srv6_locator in "{}"'.format(router)

    def _srv6_locator_default_sid(router):
        output = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
        expected = {
            "localSids":[
                {
                    "name":"End",
                    "context":"USP",
                    "prefix":"2001:db8:1:1:1::/80",
                    "owner":"static"
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_srv6_locator_default_sid, router)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _srv6_locator_default_sid in "{}"'.format(router)

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
