#include <vector>
#include <queue>

#include "host-raw-gadget.h"
#include "device-libusb.h"
#include "misc.h"
#include "regex"

std::mutex mtx;
std::queue<int> eject_command_control;

void injection(struct usb_raw_transfer_io &io, Json::Value patterns, std::string replacement_hex, bool &data_modified) {
	std::string data(io.data, io.inner.length);
	std::string replacement = hexToAscii(replacement_hex);
	for (unsigned int j = 0; j < patterns.size(); j++) {
		std::string pattern_hex = patterns[j].asString();
		std::string pattern = hexToAscii(pattern_hex);

		std::string::size_type pos = data.find(pattern);
		while (pos != std::string::npos) {
			if (data.length() - pattern.length() + replacement.length() > 1023)
				break;

			data = data.replace(pos, pattern.length(), replacement);
			printf("Modified from %s to %s at Index %ld\n", pattern_hex.c_str(), replacement_hex.c_str(), pos);
			data_modified = true;

			pos = data.find(pattern);
		}
	}

	if (data_modified) {
		io.inner.length = data.length();
		for (size_t j = 0; j < data.length(); j++) {
			io.data[j] = data[j];
		}
	}
}

void injection(struct usb_raw_control_event &event, struct usb_raw_transfer_io &io, int &injection_flags) {
	// This is just a simple injection function for control transfer.
	std::vector<std::string> injection_type{"modify", "ignore", "stall"};
	std::string transfer_type = "control";

	for (unsigned int i = 0; i < injection_type.size(); i++) {
		for (unsigned int j = 0; j < injection_config[transfer_type][injection_type[i]].size(); j++) {
			Json::Value rule = injection_config[transfer_type][injection_type[i]][j];
			if (rule["enable"].asBool() != true)
				continue;

			if (event.ctrl.bRequestType != hexToDecimal(rule["bRequestType"].asInt()) ||
			    event.ctrl.bRequest     != hexToDecimal(rule["bRequest"].asInt()) ||
			    event.ctrl.wValue       != hexToDecimal(rule["wValue"].asInt()) ||
			    event.ctrl.wIndex       != hexToDecimal(rule["wIndex"].asInt()) ||
			    event.ctrl.wLength      != hexToDecimal(rule["wLength"].asInt()))
				continue;

			printf("Matched injection rule: %s, index: %d\n", injection_type[i].c_str(), j);
			if (injection_type[i] == "modify") {
				Json::Value patterns = rule["content_pattern"];
				std::string replacement_hex = rule["replacement"].asString();
				bool data_modified = false;

				injection(io, patterns, replacement_hex, data_modified);
				if (!(event.ctrl.bRequestType & USB_DIR_IN))
					event.ctrl.wLength = io.inner.length;
			}
			else if (injection_type[i] == "ignore") {
				printf("Ignore this control transfer\n");
				injection_flags = USB_INJECTION_FLAG_IGNORE;
			}
			else if (injection_type[i] == "stall") {
				injection_flags = USB_INJECTION_FLAG_STALL;
			}
		}
	}
}

void injection(struct usb_raw_transfer_io &io, struct usb_endpoint_descriptor ep, std::string transfer_type) {
	// This is just a simple injection function for int and bulk transfer.
	for (unsigned int i = 0; i < injection_config[transfer_type].size(); i++) {
		Json::Value rule = injection_config[transfer_type][i];
		if (rule["enable"].asBool() != true ||
		    hexToDecimal(rule["ep_address"].asInt()) != ep.bEndpointAddress)
			continue;

		Json::Value patterns = rule["content_pattern"];
		std::string replacement_hex = rule["replacement"].asString();
		bool data_modified = false;

		injection(io, patterns, replacement_hex, data_modified);

		if (data_modified)
			break;
	}
}

void printData(struct usb_raw_transfer_io io, __u8 bEndpointAddress, std::string transfer_type, std::string dir) {
	printf("Sending data to EP%x(%s_%s):", bEndpointAddress,
		transfer_type.c_str(), dir.c_str());
	for (unsigned int i = 0; i < io.inner.length; i++) {
		printf(" %02hhx", (unsigned)io.data[i]);
	}
	printf("\n");
}

void *ep_loop_write(void *arg) {
	// Enable asynchronous cancellation
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	// Set cancellation type to deferred cancellation
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	struct thread_info thread_info = *((struct thread_info*) arg);
	int fd = thread_info.fd;
	int ep_num = thread_info.ep_num;
	struct usb_endpoint_descriptor ep = thread_info.endpoint;
	std::string transfer_type = thread_info.transfer_type;
	std::string dir = thread_info.dir;
	std::deque<usb_raw_transfer_io> *data_queue = thread_info.data_queue;
	std::mutex *data_mutex = thread_info.data_mutex;

	printf("Start writing thread for EP%02x, thread id(%d)\n",
		ep.bEndpointAddress, gettid());

	while (!please_stop_eps) {
		// Check for cancellation
		pthread_testcancel();
		assert(ep_num != -1);
		if (data_queue->size() == 0) {
			usleep(100);
			continue;
		}

		data_mutex->lock();
		struct usb_raw_transfer_io io = data_queue->front();
		data_queue->pop_front();
		data_mutex->unlock();

		if (verbose_level >= 2)
			printData(io, ep.bEndpointAddress, transfer_type, dir);

		if (ep.bEndpointAddress & USB_DIR_IN) {
			int rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io *)&io);
			if (rv >= 0) {
				printf("EP%x(%s_%s): wrote %d bytes to host\n", ep.bEndpointAddress,
					transfer_type.c_str(), dir.c_str(), rv);
			}

			//stop usb tcpdump when write eject command  response
			int item = 0;
			{
				std::lock_guard<std::mutex> lock(mtx);
				if (!eject_command_control.empty()) {
					item = eject_command_control.front();
					eject_command_control.pop();
				}
			}
			if (item == 1) {
				//stop usb_tcpdump
				std::string pcap_file_name = pcap_file();
				std::string pcap_file_save_name = pcap_file_save();
				//stop tcpdump will cause usb_raw_event_fetch receive EINTR,
				//will casue EP0 thread stop, should catch this except in EP0
				//thread
				stop_tcpdump_usbmon(pcap_pid, pcap_file_name, pcap_file_save_name);
				//here not restart all process, need start tcpdump process 
				pcap_pid = start_tcpdump_usbmon(bus_number, pcap_file_name);

			}
		}
		else {
			int length = io.inner.length;
			unsigned char *data = new unsigned char[length];
			memcpy(data, io.data, length);
			send_data(ep.bEndpointAddress, ep.bmAttributes, data, length);

			if (data)
				delete[] data;
		}
	}

	printf("End writing thread for EP%02x, thread id(%d)\n",
		ep.bEndpointAddress, gettid());
	return NULL;
}

void *ep_loop_read(void *arg) {
	// Enable asynchronous cancellation
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	// Set cancellation type to deferred cancellation
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	struct thread_info thread_info = *((struct thread_info*) arg);
	int fd = thread_info.fd;
	int ep_num = thread_info.ep_num;
	struct usb_endpoint_descriptor ep = thread_info.endpoint;
	std::string transfer_type = thread_info.transfer_type;
	std::string dir = thread_info.dir;
	std::deque<usb_raw_transfer_io> *data_queue = thread_info.data_queue;
	std::mutex *data_mutex = thread_info.data_mutex;

	printf("Start reading thread for EP%02x, thread id(%d)\n",
		ep.bEndpointAddress, gettid());

	while (!please_stop_eps) {
		// Check for cancellation
		pthread_testcancel();
		assert(ep_num != -1);
		struct usb_raw_transfer_io io;

		if (ep.bEndpointAddress & USB_DIR_IN) {
			unsigned char *data = NULL;
			int nbytes = -1;

			if (data_queue->size() >= 32) {
				usleep(200);
				continue;
			}

			receive_data(ep.bEndpointAddress, ep.bmAttributes, ep.wMaxPacketSize, &data, &nbytes, 0);

			if (nbytes >= 0) {
				memcpy(io.data, data, nbytes);
				io.inner.ep = ep_num;
				io.inner.flags = 0;
				io.inner.length = nbytes;

				if (injection_enabled)
					injection(io, ep, transfer_type);

				data_mutex->lock();
				data_queue->push_back(io);
				data_mutex->unlock();
				if (verbose_level)
					printf("EP%x(%s_%s): USB_DIR_IN enqueued %d bytes to queue\n", ep.bEndpointAddress,
							transfer_type.c_str(), dir.c_str(), nbytes);
			}


			if (data)
				delete[] data;
		}
		else {
			io.inner.ep = ep_num;
			io.inner.flags = 0;
			io.inner.length = sizeof(io.data);

			int rv = usb_raw_ep_read(fd, (struct usb_raw_ep_io *)&io);
			if (rv >= 0) {
				printf("EP%x(%s_%s): read %d bytes from host\n", ep.bEndpointAddress,
						transfer_type.c_str(), dir.c_str(), rv);
				io.inner.length = rv;

				if (injection_enabled)
					injection(io, ep, transfer_type);

				data_mutex->lock();
				data_queue->push_back(io);
				data_mutex->unlock();
				if (verbose_level)
					printf("EP%x(%s_%s): USB_DIR_OUT enqueued %d bytes to queue\n", ep.bEndpointAddress,
							transfer_type.c_str(), dir.c_str(), rv);
			}
		}
	}

	printf("End reading thread for EP%02x, thread id(%d)\n",
		ep.bEndpointAddress, gettid());
	return NULL;
}

void process_eps(int fd, int config, int interface, int altsetting) {
	struct raw_gadget_altsetting *alt = &host_device_desc.configs[config]
					.interfaces[interface].altsettings[altsetting];

	printf("Activating %d endpoints on interface %d\n", (int)alt->interface.bNumEndpoints, interface);

	for (int i = 0; i < alt->interface.bNumEndpoints; i++) {
		struct raw_gadget_endpoint *ep = &alt->endpoints[i];

		int addr = usb_endpoint_num(&ep->endpoint);
		assert(addr != 0);

		ep->thread_info.fd = fd;
		ep->thread_info.endpoint = ep->endpoint;
		ep->thread_info.data_queue = new std::deque<usb_raw_transfer_io>;
		ep->thread_info.data_mutex = new std::mutex;

		switch (usb_endpoint_type(&ep->endpoint)) {
		case USB_ENDPOINT_XFER_ISOC:
			ep->thread_info.transfer_type = "isoc";
			break;
		case USB_ENDPOINT_XFER_BULK:
			ep->thread_info.transfer_type = "bulk";
			break;
		case USB_ENDPOINT_XFER_INT:
			ep->thread_info.transfer_type = "int";
			break;
		default:
			printf("transfer_type %d is invalid\n", usb_endpoint_type(&ep->endpoint));
			assert(false);
		}

		if (usb_endpoint_dir_in(&ep->endpoint))
			ep->thread_info.dir = "in";
		else
			ep->thread_info.dir = "out";
		int map_eps = host_device_eps_map[ep->thread_info.endpoint.bEndpointAddress];
		if (host_device_eps_map[ep->thread_info.endpoint.bEndpointAddress]) {
			struct usb_endpoint_descriptor temp_endpoint = ep->thread_info.endpoint;
			temp_endpoint.bEndpointAddress = map_eps;
			ep->thread_info.ep_num = usb_raw_ep_enable(fd, &temp_endpoint);
		}
		else {
			ep->thread_info.ep_num = usb_raw_ep_enable(fd, &ep->thread_info.endpoint);
		}			
		
		printf("%s_%s: addr = %u, ep = #%d\n",
			ep->thread_info.transfer_type.c_str(),
			ep->thread_info.dir.c_str(),
			addr, ep->thread_info.ep_num);

		if (verbose_level)
			printf("Creating thread for EP%02x\n",
				ep->thread_info.endpoint.bEndpointAddress);
		pthread_create(&ep->thread_read, 0,
			ep_loop_read, (void *)&ep->thread_info);
		pthread_create(&ep->thread_write, 0,
			ep_loop_write, (void *)&ep->thread_info);
	}

	printf("process_eps done\n");
}

void terminate_eps(int fd, int config, int interface, int altsetting) {
	struct raw_gadget_altsetting *alt = &host_device_desc.configs[config]
					.interfaces[interface].altsettings[altsetting];


	for (int i = 0; i < alt->interface.bNumEndpoints; i++) {
		struct raw_gadget_endpoint *ep = &alt->endpoints[i];
		/*When a child thread uses wait_for_completion_interruptible()
		and the main thread calls pthread_join(), the main thread may
		get blocked indefinitely because wait_for_completion_interruptible()
		does not return until the completion of the associated task or until
		it is interrupted.This situation occurs because pthread_join() waits
		for the child thread to exit before continuing.*/
		if (ep->thread_read) {
			pthread_cancel(ep->thread_read);
			if (pthread_join(ep->thread_read, NULL))
				fprintf(stderr, "Error join thread_read\n");
		}
		if (ep->thread_write) {
			pthread_cancel(ep->thread_write);
			if (pthread_join(ep->thread_write, NULL))
				fprintf(stderr, "Error join thread_write\n");
		}
		ep->thread_read = 0;
		ep->thread_write = 0;

		usb_raw_ep_disable(fd, ep->thread_info.ep_num);
		ep->thread_info.ep_num = -1;

		delete ep->thread_info.data_queue;
		delete ep->thread_info.data_mutex;
	}

}

void ep0_loop(int fd) {
	bool set_configuration_done_once = false;
	int prev_desired_config = -1;
	bool get_device_done_once = false;

	printf("Start for EP0, thread id(%d)\n", gettid());

	if (verbose_level)
		print_eps_info(fd);

	while (!please_stop_ep0) {
		struct usb_raw_control_event event;
		event.inner.type = 0;
		event.inner.length = sizeof(event.ctrl);

		usb_raw_event_fetch(fd, (struct usb_raw_event *)&event);
		log_event((struct usb_raw_event *)&event);

		if (event.inner.length == 4294967295) {
			//all usb hotplug remove will cause restart usbbr 
			//when in this, is big card reader receive eject 
			//command stop tcpdump process cause, continue
			continue;

			//printf("End for EP0, thread id(%d)\n", gettid());
			//return;
		}

		if (event.inner.type != USB_RAW_EVENT_CONTROL)
			continue;

		struct usb_raw_transfer_io io;
		io.inner.ep = 0;
		io.inner.flags = 0;
		io.inner.length = event.ctrl.wLength;

		int injection_flags = USB_INJECTION_FLAG_NONE;
		int nbytes = 0;
		int result = 0;
		unsigned char *control_data = new unsigned char[event.ctrl.wLength];


		int rv = -1;
		if (event.ctrl.bRequestType & USB_DIR_IN) {
                        if (event.ctrl.bRequestType == 0x80 && event.ctrl.bRequest == 0x06
                        	&&event.ctrl.wLength==18) { //two get device need restart
                                if (get_device_done_once) {
					//stop usb_tcpdump
					std::string pcap_file_name = pcap_file();
					std::string pcap_file_save_name = pcap_file_save();
					stop_tcpdump_usbmon(pcap_pid, pcap_file_name, pcap_file_save_name);
                                        //must close raw_gadget fd before restart self
                                        close(raw_gadget_fd);
                                        //restart self becasue device remove
                                        if (execv(self_prog[0], self_prog) == -1)
                                                printf("restart self process failed\n");

                                }
                        }


			result = control_request(&event.ctrl, &nbytes, &control_data, 1000);
			if (result == 0) {
				memcpy(&io.data[0], control_data, nbytes);
				io.inner.length = nbytes;

				if (injection_enabled) {
					injection(event, io, injection_flags);
					switch(injection_flags) {
					case USB_INJECTION_FLAG_NONE:
						break;
					case USB_INJECTION_FLAG_IGNORE:
						delete[] control_data;
						continue;
					case USB_INJECTION_FLAG_STALL:
						delete[] control_data;
						usb_raw_ep0_stall(fd);
						continue;
					default:
						printf("[Warning] Unknown injection flags: %d\n", injection_flags);
						break;
					}
				}
				if ((event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
					event.ctrl.bRequest == USB_REQ_GET_DESCRIPTOR) {
					if((event.ctrl.wValue >> 8) == USB_DT_DEVICE) {
						struct usb_device_descriptor* pdata = (struct usb_device_descriptor*)&io.data;
						pdata->bMaxPacketSize0 = 64;
						if(pdata->idVendor == 0x2ce3 || pdata->idVendor == 0x058f) {
							pdata->bcdUSB = 0x0200;
							pdata->bcdDevice = 0x0302;
							pdata->idVendor = 0x076b;
							pdata->idProduct = 0x3021;
						}
					}
					else if((event.ctrl.wValue >> 8) == USB_DT_CONFIG) {
						if (host_device_eps_map.size() != 0) {
							std::string data(io.data, io.inner.length);
							for (auto it = host_device_eps_map.begin(); it != host_device_eps_map.end(); ++it) {
								//bLength+bDescriptorType+bEndpointAddress
								char pattern[3] = { char(0x07), char(0x05),char(it->first) };
								std::string str_pattern(pattern, 3);
								char replacement[3] = { char(0x07), char(0x05), char(it->second) };
								std::string str_replacement(replacement, 3);
								findAndReplaceAll(data, str_pattern, str_replacement);
							}
							io.inner.length = data.length();
							for (size_t j = 0; j < data.length(); j++) {
								io.data[j] = data[j];
							}
						}
						if (host_device_desc.device.idVendor == 0x077a){
							std::string data1(io.data, io.inner.length);
							char pattern1[4] = { char(0x02), char(0x03), char(0x40),char(0x00) };
							std::string str_pattern1(pattern1, 4);
							char replacement1[4] = { char(0x82), char(0x02), char(0x40), char(0x00) };
							std::string str_replacement1(replacement1, 4);
							findAndReplaceAll(data1, str_pattern1, str_replacement1);
                                                	io.inner.length = data1.length();
                                                	for (size_t j = 0; j < data1.length(); j++) {
                                                    		io.data[j] = data1[j];
                                                	}
						}

					}
					
				}

				if (verbose_level >= 2)
					printData(io, 0x00, "control", "in");

				rv = usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
				printf("ep0: transferred %d bytes (in)\n", rv);
			}
			else {
				usb_raw_ep0_stall(fd);
			}
		}
		else {
			rv = usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)&io);

			if (event.ctrl.bRequestType == 0x00 && event.ctrl.bRequest == 0x09) { // Set configuration
				int desired_config = -1;
				for (int i = 0; i < host_device_desc.device.bNumConfigurations; i++) {
					if (host_device_desc.configs[i].config.bConfigurationValue == event.ctrl.wValue) {
						desired_config = i;
						break;
					}
				}
				if (desired_config < 0 || prev_desired_config == desired_config) {
					printf("[Warning] Skip changing configuration, wValue(%d) is invalid\n", event.ctrl.wValue);
					continue;
				}

				struct raw_gadget_config *config = &host_device_desc.configs[desired_config];

				if (set_configuration_done_once) { // Need to stop all threads for eps and cleanup
					printf("Changing configuration\n");
					for (int i = 0; i < config->config.bNumInterfaces; i++) {
						struct raw_gadget_interface *iface = &config->interfaces[i];
						int interface_num = iface->altsettings[iface->current_altsetting]
							.interface.bInterfaceNumber;
						terminate_eps(fd, host_device_desc.current_config, i,
								iface->current_altsetting);
						release_interface(interface_num);
					}
				}
				
				usb_raw_configure(fd);
				set_configuration(config->config.bConfigurationValue);
				host_device_desc.current_config = desired_config;

				for (int i = 0; i < config->config.bNumInterfaces; i++) {
					struct raw_gadget_interface *iface = &config->interfaces[i];
					iface->current_altsetting = 0;
					int interface_num = iface->altsettings[0].interface.bInterfaceNumber;
					claim_interface(interface_num);
					process_eps(fd, desired_config, i, 0);
				}
				prev_desired_config = desired_config;
				set_configuration_done_once = true;
                                get_device_done_once = true;
			}
			else if (event.ctrl.bRequestType == 0x01 && event.ctrl.bRequest == 0x0b) { // Set interface/alt_setting
				struct raw_gadget_config* config =
					&host_device_desc.configs[host_device_desc.current_config];

				int desired_interface = -1;
				for (int i = 0; i < config->config.bNumInterfaces; i++) {
					if (config->interfaces[i].altsettings[0].interface.bInterfaceNumber ==
							event.ctrl.wIndex) {
						desired_interface = i;
						break;
					}
				}
				if (desired_interface < 0) {
					printf("[Warning] Skip changing interface, wIndex(%d) is invalid\n", event.ctrl.wIndex);
					continue;
				}

				struct raw_gadget_interface *iface = &config->interfaces[desired_interface];

				int desired_altsetting = -1;
				for (int i = 0; i < iface->num_altsettings; i++) {
					if (iface->altsettings[i].interface.bAlternateSetting == event.ctrl.wValue) {
						desired_altsetting = i;
						break;
					}
				}
				if (desired_altsetting < 0) {
					printf("[Warning] Skip changing alt_setting, wValue(%d) is invalid\n", event.ctrl.wValue);
					continue;
				}

				struct raw_gadget_altsetting *alt = &iface->altsettings[desired_altsetting];

				printf("Changing interface/altsetting\n");

				terminate_eps(fd, host_device_desc.current_config,
					desired_interface, iface->current_altsetting);
				set_interface_alt_setting(alt->interface.bInterfaceNumber,
					alt->interface.bAlternateSetting);
				process_eps(fd, host_device_desc.current_config,
					desired_interface, desired_altsetting);
				iface->current_altsetting = desired_altsetting;
			}
			else if (event.ctrl.bRequestType == 0x21 && event.ctrl.bRequest == 0x09 && host_device_desc.device.idVendor == 0x077a) {
					struct raw_gadget_altsetting *alt = &host_device_desc.configs[0]
					.interfaces[0].altsettings[0];
					for (int i = 0; i < alt->interface.bNumEndpoints; i++) {
						struct raw_gadget_endpoint *ep = &alt->endpoints[i];
						if (!usb_endpoint_dir_in(&ep->endpoint)) {
							int length = io.inner.length;
							unsigned char *data = new unsigned char[length];
							memcpy(data, io.data, length);
							//searh eject command to notify stop tcpdump
							char eject_command[5] = { char(0x00), char(0x03), char(0x43), char(0x33), char(0x30) };
							std::string data_command(io.data, io.inner.length);
							std::string eject_command_str(eject_command, sizeof(eject_command));
							size_t pos = data_command.find(eject_command_str);
							//eject command run, notify ep81 write to host thread
							if (pos != std::string::npos) {
								{
									std::lock_guard<std::mutex> lock(mtx);
									eject_command_control.push(1);
								}
								
							}

							send_data(ep->endpoint.bEndpointAddress, ep->endpoint.bmAttributes, data, length);
							if (verbose_level >= 2)
								printData(io, 0x00, "control", "out");

						}
					}

			}
			else {
				if (injection_enabled) {
					injection(event, io, injection_flags);
					switch(injection_flags) {
					case USB_INJECTION_FLAG_NONE:
						break;
					case USB_INJECTION_FLAG_IGNORE:
						delete[] control_data;
						continue;
					case USB_INJECTION_FLAG_STALL:
						delete[] control_data;
						usb_raw_ep0_stall(fd);
						continue;
					default:
						printf("[Warning] Unknown injection flags: %d\n", injection_flags);
						break;
					}
				}

				memcpy(control_data, io.data, event.ctrl.wLength);

				if (verbose_level >= 2)
					printData(io, 0x00, "control", "out");

				result = control_request(&event.ctrl, &nbytes, &control_data, 1000);
				if (result == 0) {
					printf("ep0: transferred %d bytes (out)\n", rv);
				}
				else {
					if (event.ctrl.bRequestType == 0x21
						&& event.ctrl.bRequest == 0x0a
						&& event.ctrl.wIndex != 0) {
						continue;
					}
					else {
						usb_raw_ep0_stall(fd);
					}
				}
			}
		}

		delete[] control_data;
	}

	struct raw_gadget_config *config = &host_device_desc.configs[host_device_desc.current_config];

	for (int i = 0; i < config->config.bNumInterfaces; i++) {
		struct raw_gadget_interface *iface = &config->interfaces[i];
		int interface_num = iface->altsettings[iface->current_altsetting]
			.interface.bInterfaceNumber;
		terminate_eps(fd, host_device_desc.current_config, i,
				iface->current_altsetting);
		release_interface(interface_num);
	}

	printf("End for EP0, thread id(%d)\n", gettid());
}
