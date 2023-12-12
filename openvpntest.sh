#!/usr/bin/env bash
export PYTHONPATH=../tls-dissector/

testlist=("aes128_sha1_no_tls-auth" "aes128_sha1" "aes128_sha256" "aes128_sha512" "aes256_sha512" "aes256gcm_sha512" "aes256gcm_sha512_exporter" )

for test in "${testlist[@]}";
do
	rm -rf /tmp/log.txt
	./openvpn-dissector.py -p ./testvect/trafic_openvpn_$test.pcap -k ./testvect/trafic_openvpn_$test.key -c ./testvect/$test.ovpn > /tmp/log.txt 2>/dev/null
	diff /tmp/log.txt ./testvect/trafic_openvpn_$test.result
	ret=$?

	if [ $ret -ne 0 ]
	then
		echo "test openvpn_$test KO :-("
	else
		echo "test openvpn_$test OK :-)"
	fi
done

rm -rf /tmp/log.txt
