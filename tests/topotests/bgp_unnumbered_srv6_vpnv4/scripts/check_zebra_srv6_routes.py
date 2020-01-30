from lutil import luCommand

def check_prefix(jobj, prefix_key, proto):
    prefix = jobj[prefix_key]
    if prefix == None:
        luResult('r1', False, 'prefix {}: not found'.format(prefix_key))
        return
    if len(prefix) != 1:
        luResult('r1', False, 'prefix {}: expected singlepath'.format(prefix_key))
        return
    if prefix[0]['protocol'] != proto:
        luResult('r1', False, 'prefix {}: proto is not {}'.format(prefix_key, proto))
        return
    if prefix[0]['selected'] != True:
        luResult('r1', False, 'prefix {}: not selected'.format(prefix_key))
        return
    if len(prefix[0]['nexthops']) != 1:
        luResult('r1', False, 'prefix {}: n-nh isnt 1'.format(prefix_key))
        return
    if prefix[0]['nexthops'][0]['fib'] != True:
        luResult('r1', False, 'prefix {}: nexthop-fib isnt active'.format(prefix_key))
        return
    if prefix[0]['nexthops'][0]['active'] != True:
        luResult('r1', False, 'prefix {}: isnt active nexthop'.format(prefix_key))
        return
    luResult('r1', True, 'zebra ipv6 route {} is valid'.format(prefix_key))

jobj = luCommand('r2','vtysh -c "show ipv6 route json"', returnJson=True)
check_prefix(jobj, '2001:db8:2:2:fc3::/80', 'bgp')
check_prefix(jobj, '2001:db8:2:2:fc4::/80', 'bgp')

jobj = luCommand('r1','vtysh -c "show ip route vrf vrf1 json"', returnJson=True)
check_prefix(jobj, '10.1.0.0/24', 'connected')
check_prefix(jobj, '10.3.0.0/24', 'bgp')

jobj = luCommand('r1','vtysh -c "show ip route vrf vrf2 json"', returnJson=True)
check_prefix(jobj, '10.2.0.0/24', 'connected')
check_prefix(jobj, '10.4.0.0/24', 'bgp')
