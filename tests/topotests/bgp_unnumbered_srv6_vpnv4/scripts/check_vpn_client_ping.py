from lutil import luCommand

luCommand('c1', 'ping -I 10.1.0.2 10.1.0.1 -c 1', ' 0. packet loss','wait','c1->r1 ping')
luCommand('c1', 'ping -I 10.1.0.2 10.3.0.1 -c 1', ' 0. packet loss','wait','c1->r1->r2 ping')
luCommand('c1', 'ping -I 10.1.0.2 10.3.0.2 -c 1', ' 0. packet loss','wait','c1->r1->r2->c3 ping')

luCommand('c2', 'ping -I 10.2.0.2 10.2.0.1 -c 1', ' 0. packet loss','wait','c2->r1 ping')
luCommand('c2', 'ping -I 10.2.0.2 10.4.0.1 -c 1', ' 0. packet loss','wait','c2->r1->r2 ping')
luCommand('c2', 'ping -I 10.2.0.2 10.4.0.2 -c 1', ' 0. packet loss','wait','c2->r1->r2->c4 ping')

luCommand('c3', 'ping -I 10.3.0.2 10.3.0.1 -c 1', ' 0. packet loss','wait','c3->r2 ping')
luCommand('c3', 'ping -I 10.3.0.2 10.1.0.1 -c 1', ' 0. packet loss','wait','c3->r2->r1 ping')
luCommand('c3', 'ping -I 10.3.0.2 10.1.0.2 -c 1', ' 0. packet loss','wait','c3->r2->r1->c1 ping')

luCommand('c4', 'ping -I 10.4.0.2 10.4.0.1 -c 1', ' 0. packet loss','wait','c4->r2 ping')
luCommand('c4', 'ping -I 10.4.0.2 10.2.0.1 -c 1', ' 0. packet loss','wait','c4->r2->r1 ping')
luCommand('c4', 'ping -I 10.4.0.2 10.2.0.2 -c 1', ' 0. packet loss','wait','c4->r2->r1->c2 ping')
