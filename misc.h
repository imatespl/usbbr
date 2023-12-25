#include <assert.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <getopt.h>
#include <signal.h>
#include <chrono>
#include <sys/stat.h>
#include <linux/usb/ch9.h>
#include <jsoncpp/json/json.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mutex>

extern int verbose_level;
extern bool please_stop_ep0;
extern volatile bool please_stop_eps;

extern bool injection_enabled;
extern std::string injection_file;
extern Json::Value injection_config;

extern std::string conf_file;
extern Json::Value usbbr_config;

std::string hexToAscii(std::string input);
int hexToDecimal(int input);

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr);

extern char** self_prog;
extern int raw_gadget_fd;
extern pid_t pcap_pid;
extern int start_tcpdump_usbmon(int bus_num, std::string pcap_file);
extern int stop_tcpdump_usbmon(pid_t pcap_pid, std::string pcap_file, std::string pcap_file_save);
extern void stop_all_tcpdump_usbmon();
extern std::string pcap_file();
extern std::string pcap_file_save();
extern std::mutex pcap_mtx;
extern pthread_t pcap_monitor_size_thread;
extern void* pcap_file_max_and_resave(void *arg __attribute__((unused)));

bool needSaveData(std::vector<unsigned char>& data);
