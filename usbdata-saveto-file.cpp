#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <pcap.h>
#include <sys/time.h>
#include <stdint.h>
#include <cstdlib>
#include <usbdata-saveto-file.h>
#include <misc.h>

size_t file_size = 0;
size_t max_file_size = 1024 * 1024; //max size is 1M;
void usb_linux_64_byte_header(pcap_usb_header_mmapped* pusbhdr, pcap_usb_data* pud ) {
	struct timeval    now;
	gettimeofday(&now, NULL);

	*pusbhdr = {
		.id = (uint64_t) rand() % 1000000000,
		.event_type = udp->event_type,
		.transfer_type = udp->transfer_type,
		.endpoint_number = udp->endpoint_number,
		.device_address = udp->device_address,
		.bus_id = udp->bus_id,
		.setup_flag = 0x2d,
		.data_flag = 0x00,
		.ts_sec = (int64_t)now.tv_sec,
		.ts_usec = (int32_t)now.tv_usec,
		.status = 0,
		.urb_len = 64,
		.data_len = udp->data_len,
		.s = 0,
		.interval = 0,
		.start_frame = 0,
		.xfer_flags = 0x00000200,
		.ndesc = 0
	};

}

// Function for the file writing thread
void writeUSBPcapThread() {
	// Set up libpcap for writing
	pcap_t* pcap = pcap_open_dead(DLT_USB_LINUX_MMAPPED, MAX_PACKET_SIZE);
	pcap_dumper_t* pcap_dumper = pcap_dump_open(pcap, PCAP_FILE);
	pcap_usb_header_mmapped pusbhdr;

	while (true) {
		std::unique_lock<std::mutex> lock(usbDataMutex);

		// Wait for data to be available or processing to be done
		usbDataCondition.wait(lock, [&] { return !usbDataQueue.empty() || isDataProcessingDone; });

		// Process data and write to file
		while (!dataQueue.empty()) {
			pcap_usb_data pud = usbDataQueue.front();
			usb_linux_64_byte_header(&pusbhdr, &pud);
			// Convert std::vector to unsigned char[]
			size_t dataVectorSize = pud.data.size();
			if (dataVectorSize < 64) {
				//need add zero to data end to len 64
				unsigned char* dataBytes = new unsigned char[64];
				std::memset(dataBytes, 0, 64);
				for (size_t i = 0; i < dataVectorSize; ++i) {
					dataBytes[i] = data[i];
				}
			}
			else {
				unsigned char* dataBytes = new unsigned char[dataVectorSize];
				for (size_t i = 0; i < dataVectorSize; ++i) {
					dataBytes[i] = data[i];
				}
			}
			size_t pcap_total_len = sizeof(pcap_usb_header_mmapped) + sizeof(dataBytes) / sizeof(dataBytes[0]);
			unsigned char* pcapDataBytes = new unsigned char[pcap_total_len];
			memcpy(pcapDataBytes, (const unsigned char *) &pcap_usb_header_mmapped, sizeof(pcap_usb_header_mmapped));
			memcpy(pcapDataBytes + sizeof(pcap_usb_header_mmapped), dataBytes, sizeof(dataBytes) / sizeof(dataBytes[0]));
			// Write the received data to PCAP file
			struct pcap_pkthdr pkthdr;
			gettimeofday(&pkthdr.ts, NULL);
			pkthdr.caplen = pcap_total_len;
			pkthdr.len = pcap_total_len;
			pcap_dump((u_char*)pcap_dumper, &pkthdr, dataBytes);

			//if file > 1M need save new file;
			file_size += pcap_total_len;
			if (file_size >= max_file_size || pud.isNeedResaveFile) {
    				pcap_dump_close(pcapDumper);
    				pcap_close(pcap);
				std::string save_command = "pcap-process.sh "+PCAP_FILE+" "+pcap_file_save()+"&";
				system(save_command.c_str());
				//reinit pcap dumper
				pcap_t* pcap = pcap_open_dead(DLT_USB_LINUX_MMAPPED, MAX_PACKET_SIZE);
				pcap_dumper_t* pcap_dumper = pcap_dump_open(pcap, PCAP_FILE);
			}
			delete[] dataBytes;
			delete[] pcapDataBytes;
			usbDataQueue.pop();

		}

		// Check if data processing is done
		if (isDataProcessingDone) {
			break;
		}
	}

}

void sendDataToPcapFile(pcap_usb_data* pud) {

	{
            std::unique_lock<std::mutex> lock(usbDataMutex);

            // Enqueue the data to the buffer
            dataBuffer.push_back(*pud);
        }
	// Notify the file writing thread that data is available
        bufferCondition.notify_one();
}
