#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <pcap.h>
#include <sys/time.h>
#include <stdint.h>
#include <cstdlib>
#include <usbdata-saveto-file.h>

void usb_linux_64_byte_header(pcap_usb_header_mmapped* pusbhdr, uint8_t etype, uint8_t trantype,
	uint8_t endpoint, uint8_t devaddr, uint8_t busid, uint32_t datalen ) {
	struct timeval    now;
	gettimeofday(&now, NULL);

	*pusbhdr = {
		.id = (uint64_t) rand() % 1000000000,
		.event_type = etype,
		.transfer_type = trantype,
		.endpoint_number = endpoint,
		.device_address = devaddr,
		.bus_id = busid,
		.setup_flag = 0x2d,
		.data_flag = 0x00,
		.ts_sec = (int64_t)now.tv_sec,
		.ts_usec = (int32_t)now.tv_usec,
		.status = 0,
		.urb_len = 64,
		.data_len = datalen,
		.s = 0,
		.interval = 0,
		.start_frame = 0,
		.xfer_flags = 0x00000200,
		.ndesc = 0
	};

}

// Function for the file writing thread
void writeFileThread() {
	// Set up libpcap for writing
	std::string usbpcap = "/data/usb_running.pcap";
	pcap_t* pcap = pcap_open_dead(DLT_USB, MAX_PACKET_SIZE);
	pcap_dumper_t* pcap_dumper = pcap_dump_open(pcap, usbpcap);

	while (true) {
		std::unique_lock<std::mutex> lock(usbDataMutex);

		// Wait for data to be available or processing to be done
		usbDataCondition.wait(lock, [&] { return !usbDataQueue.empty() || isDataProcessingDone; });

		// Process data and write to file
		while (!dataQueue.empty()) {
			std::vector<unsigned char> data = usbDataQueue.front();
			// Convert std::vector to unsigned char[]
			size_t dataVectorSize = data.size();
			unsigned char* dataBytes = new unsigned char[dataVectorSize];
			for (size_t i = 0; i < dataVectorSize; ++i) {
				dataBytes[i] = data[i];
			}

			// Write the received data to PCAP file
			struct pcap_pkthdr pkthdr;
			gettimeofday(&pkthdr.ts, NULL);
			pkthdr.caplen = dataVectorSize;
			pkthdr.len = dataVectorSize;
			pcap_dump((u_char*)pcap_dumper, &pkthdr, dataBytes);
			delete[] dataBytes;
			usbDataQueue.pop();
			
		}

		// Check if data processing is done
		if (isDataProcessingDone) {
			break;
		}
	}

}
