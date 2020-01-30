from lutil import luCommand
from bgprib import bgpribRequireVpnRoutes,bgpribRequireUnicastRoutes

routes = [
    {'p':'10.1.0.0/24', 'n':'0.0.0.0' },
    {'p':'10.3.0.0/24', 'n':'fe80::5054:ff:fe22:0' },
]
bgpribRequireUnicastRoutes('r1', 'ipv4', 'vrf1', 'routes in r1 vrf1', routes)

routes = [
    {'p':'10.2.0.0/24', 'n':'0.0.0.0' },
    {'p':'10.4.0.0/24', 'n':'fe80::5054:ff:fe22:0' },
]
bgpribRequireUnicastRoutes('r1', 'ipv4', 'vrf2', 'routes in r1 vrf2', routes)

routes = [
    {'rd':'1:1', 'p':'10.1.0.0/24', 'n':'0.0.0.0' },
    {'rd':'1:2', 'p':'10.2.0.0/24', 'n':'0.0.0.0' },
    {'rd':'2:1', 'p':'10.3.0.0/24', 'n':'fe80::5054:ff:fe22:0' },
    {'rd':'2:2', 'p':'10.4.0.0/24', 'n':'fe80::5054:ff:fe22:0' },
]
bgpribRequireVpnRoutes('r1', 'vpnv4 routes on r1', routes)
