LDFLAG=-lusb-1.0 -pthread -ljsoncpp -lpcap

ifndef CFLAGS
	ifeq ($(TARGET),Debug)
		CFLAGS=-Wall -Wextra -g
	else
		CFLAGS=-Wall -Wextra -O2
	endif
endif

.PHONY: all clean

usbbr: usb-proxy.o host-raw-gadget.o device-libusb.o proxy.o misc.o usbdata-saveto-file.o
	g++ usb-proxy.o host-raw-gadget.o device-libusb.o proxy.o misc.o usbdata-saveto-file.o $(LDFLAG) -o usbbr

%.o: %.cpp %.h
	g++ $(CFLAGS) -c $<

%.o: %.cpp
	g++ $(CFLAGS) -c $<

clean:
	-rm *.o
	-rm usbbr
