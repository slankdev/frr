#!/usr/bin/env python

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

from lib.ltemplate import *

def test_check_vpn_client_ping():
    CliOnFail = None
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', mpls=False)'
    ltemplateTest('scripts/check_vpn_client_ping.py', False, CliOnFail, CheckFunc)

def test_check_zebra_srv6_manager():
    CliOnFail = None
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', mpls=False)'
    ltemplateTest('scripts/check_zebra_srv6_manager.py', False, CliOnFail, CheckFunc)

def test_check_zebra_srv6_routes():
    CliOnFail = None
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', mpls=False)'
    ltemplateTest('scripts/check_zebra_srv6_routes.py', False, CliOnFail, CheckFunc)

def test_check_bgp_rib():
    CliOnFail = None
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', mpls=False)'
    ltemplateTest('scripts/check_bgp_rib.py', False, CliOnFail, CheckFunc)

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
