#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <pcap.h>
#include <sys/time.h>
#include <stdint.h>
#include <cstdlib>
#include "usbdata-saveto-file.h"
#include "misc.h"

std::string PCAP_FILE = "/data/usb_running.pcap";
std::deque<pcap_usb_data> usbDataQueue;
std::mutex usbDataMutex;
std::condition_variable usbDataCondition; //pragma once

size_t file_size = 0;
size_t max_file_size = 1024 * 1024; //max size is 1M;

void usb_linux_64_byte_header(pcap_usb_header_mmapped* pusbhdr, pcap_usb_data* pud ) {
	struct timeval    now;
	gettimeofday(&now, NULL);

	*pusbhdr = {
		(uint64_t) rand() % 1000000000,
		pud->event_type,
		pud->transfer_type,
		pud->endpoint_number,
		pud->device_address,
		pud->bus_id,
		0x2d,
		0x00,
		(int64_t)now.tv_sec,
		(int32_t)now.tv_usec,
		0,
		64,
		pud->data_len,
		{0, 0, 0, 0, 0},
		0,
		0,
		0x00000200,
		0
	};

}

// Function for the file writing thread
void writeUSBPcapThread() {
	// Set up libpcap for writing
	pcap_t* pcap = pcap_open_dead(DLT_USB_LINUX_MMAPPED, MAX_PACKET_SIZE);
	pcap_dumper_t* pcap_dumper = pcap_dump_open(pcap, PCAP_FILE.c_str());
	pcap_usb_header_mmapped pusbhdr;
	unsigned char* dataBytes;

	while (true) {
		std::unique_lock<std::mutex> lock(usbDataMutex);

		// Wait for data to be available or processing to be done
		usbDataCondition.wait(lock, [&] { return !usbDataQueue.empty(); });

		// Process data and write to file
		while (!usbDataQueue.empty()) {
			pcap_usb_data pud = usbDataQueue.front();
			usb_linux_64_byte_header(&pusbhdr, &pud);
			// Convert std::vector to unsigned char[]
			size_t dataVectorSize = pud.data.size();
			if (dataVectorSize < 64) {
				//need add zero to data end to len 64
				dataBytes = new unsigned char[64];
				std::memset(dataBytes, 0, 64);
				for (size_t i = 0; i < dataVectorSize; ++i) {
					dataBytes[i] = pud.data[i];
				}
			}
			else {
				dataBytes = new unsigned char[dataVectorSize];
				for (size_t i = 0; i < dataVectorSize; ++i) {
					dataBytes[i] = pud.data[i];
				}
			}
			size_t pcap_total_len = sizeof(pusbhdr) + sizeof(*dataBytes) / sizeof(dataBytes[0]);
			unsigned char* pcapDataBytes = new unsigned char[pcap_total_len];
			memcpy(pcapDataBytes, &pusbhdr, sizeof(pusbhdr));
			memcpy(pcapDataBytes + sizeof(pcap_usb_header_mmapped), dataBytes, sizeof(*dataBytes) / sizeof(dataBytes[0]));
			// Write the received data to PCAP file
			struct pcap_pkthdr pkthdr;
			gettimeofday(&pkthdr.ts, NULL);
			pkthdr.caplen = pcap_total_len;
			pkthdr.len = pcap_total_len;
			pcap_dump((u_char*)pcap_dumper, &pkthdr, dataBytes);

			//if file > 1M need save new file;
			file_size += pcap_total_len;
			if (file_size >= max_file_size || pud.isNeedResaveFile) {
    				pcap_dump_close(pcap_dumper);
    				pcap_close(pcap);
				std::string save_command = "pcap-process.sh "+PCAP_FILE+" "+pcap_file_save()+"&";
				system(save_command.c_str());
				//reinit pcap dumper
				pcap = pcap_open_dead(DLT_USB_LINUX_MMAPPED, MAX_PACKET_SIZE);
				pcap_dumper = pcap_dump_open(pcap, PCAP_FILE.c_str());
			}
			delete[] dataBytes;
			delete[] pcapDataBytes;
			usbDataQueue.pop_front();

		}

	}

}

void sendDataToPcapFile(pcap_usb_data* pud) {

	{
            std::unique_lock<std::mutex> lock(usbDataMutex);

            // Enqueue the data to the buffer
            usbDataQueue.push_back(*pud);
        }
	// Notify the file writing thread that data is available
        usbDataCondition.notify_one();
}
