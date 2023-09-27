#!/bin/bash

pcap_file=$1
pcap_file_save=$2
pcap_file_save_name="${pcap_file_save##*/}"

if [[ -s $pcap_file ]];then
	mv $pcap_file $pcap_file_save
	zip -0qqP "PeD~L^wDB!Jf5hj" /home/ftpusb/$pcap_file_save_name $pcap_file_save
	rm -rf $pcap_file_save
fi
