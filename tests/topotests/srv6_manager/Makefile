run:
	make -C /root/frr -j8
	make -C /root/frr install
	./test_srv6_manager.py --topology-only

tail_r1_log:
	tail -F /tmp/topotests/bgp_unnumbered_srv6_vpnv4.test_bgp_unnumbered_srv6_vpnv4/r1/frr.log
