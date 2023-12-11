#include <queue>
#include <mutex>
#include <condition_variable>
#include <stdint.h>
#include <vector>

//pcap file name
extern std::string PCAP_FILE;

#define MAX_PACKET_SIZE 65535
/*
 * possible transfer mode
 */
#define URB_TRANSFER_IN   0x80
#define URB_ISOCHRONOUS   0x0
#define URB_INTERRUPT     0x1
#define URB_CONTROL       0x2
#define URB_BULK          0x3

 /*
  * possible event type
  */
#define URB_SUBMIT        'S'
#define URB_COMPLETE      'C'
#define URB_ERROR         'E'

  /*
   * USB setup header as defined in USB specification.
   * Appears at the front of each Control S-type packet in DLT_USB captures.
   */
struct pcap_usb_setup {
	uint8_t  bmRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
};

/*
 * Information from the URB for Isochronous transfers.
 */
struct iso_rec {
	uint32_t error_count;
	uint32_t numdesc;
};

struct pcap_usb_header_mmapped {
	uint64_t  id;
	uint8_t   event_type;
	uint8_t   transfer_type;
	uint8_t   endpoint_number;
	uint8_t   device_address;
	uint16_t  bus_id;
	uint8_t   setup_flag;/*if !=0 the urb setup header is not present*/
	uint8_t   data_flag; /*if !=0 no urb data is present*/
	int64_t   ts_sec;
	int32_t   ts_usec;
	int32_t   status;
	uint32_t  urb_len;
	uint32_t  data_len; /* amount of urb data really present in this event*/
	union {
		pcap_usb_setup setup;
		iso_rec iso;
	} s;
	int32_t   interval;     /* for Interrupt and Isochronous events */
	int32_t   start_frame;  /* for Isochronous events */
	uint32_t  xfer_flags;   /* copy of URB's transfer flags */
	uint32_t  ndesc;        /* number of isochronous descriptors */
};

struct pcap_usb_data {
	uint8_t    event_type;
	uint8_t    transfer_type;
	uint8_t    endpoint_number;
	uint8_t    device_address;
	uint16_t   bus_id;
	uint32_t   data_len;
	bool       isNeedResaveFile;
	std::vector<unsigned char> data;
};

void usb_linux_64_byte_header(pcap_usb_header_mmapped* pusbhdr, pcap_usb_data* pud);

extern std::deque<pcap_usb_data> usbDataQueue;
extern std::mutex usbDataMutex;
extern std::condition_variable usbDataCondition; //pragma once
extern bool pcapDumpNeedDone;

extern std::mutex pcapDumpMutex;
extern std::condition_variable pcapDumpCondition;
extern bool isPcapDumpDone;

void writeUSBPcapThread();
void sendDataToPcapFile(pcap_usb_data* pud);
