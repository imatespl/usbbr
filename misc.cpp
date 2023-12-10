#include <math.h>
#include <bits/stdc++.h>

#include "misc.h"
#include "device-libusb.h"



std::string hexToAscii(std::string input) {
	std::string output = input;
	size_t pos = output.find("\\x");
	while (pos != std::string::npos) {
		std::string substr = output.substr(pos + 2, 2);

		std::istringstream iss(substr);
		iss.flags(std::ios::hex);
		int i;
		iss >> i;
		output = output.replace(pos, 4, 1, char(i));
		pos = output.find("\\x");
	}
	return output;
}

int hexToDecimal(int input) {
	int output = 0;
	int i = 0;
	while (input != 0) {
		output += (input % 10) * pow(16, i);
		input /= 10;
		i++;
	}
	return output;
}

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr) {
	// Get the first occurrence
	size_t pos = data.find(toSearch);
	// Repeat till end is reached
	while (pos != std::string::npos)
	{
		// Replace this occurrence of Sub String
		data.replace(pos, toSearch.size(), replaceStr);
		// Get the next occurrence from the current position
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

int start_tcpdump_usbmon(int bus_num, std::string pcap_file) {
	pid_t child_pid;
	child_pid = fork();
	if (child_pid < 0) {
		printf("Fork pcap process failed\n");
		return -1;
	}
	std::string usb_interface = "usbmon" + std::to_string(bus_num);
	if (child_pid == 0) {
		execlp("/usr/bin/tcpdump", "tcpdump", "-i", usb_interface.c_str(), "-U", "-n", "-s0", "-w", pcap_file.c_str(), NULL);
		return 1;
	}
	return child_pid;
	
}

int stop_tcpdump_usbmon(pid_t pcap_pid, std::string pcap_file, std::string pcap_file_save) {
	if (kill(pcap_pid, SIGTERM) != 0) {
		printf("Kill pcap process failed，try sigkill process fork\n");
		if (kill(pcap_pid, SIGKILL) != 0) {
			printf("Kill pcap process failed, use sigkill\n");
			return -1;
		}

	}

	// Wait for the child process to finish
	int status;
	waitpid(pcap_pid, &status, 0);
	std::string save_command = "pcap-process.sh "+pcap_file+" "+pcap_file_save+"&";
	system(save_command.c_str());
	return 0;
	
}
//at process start clean all tcpdump process
void stop_all_tcpdump_usbmon() {
	system("killall -q -SIGKILL tcpdump");
}

std::string pcap_file() {
	return "/data/usb_running.pcap";
}

std::string pcap_file_save() {
	std::string pcap_file_save;
	std::ifstream inputFile("/root/.pcap_file_save");

	std::string line;
	std::getline(inputFile, line);
	int num = std::stoi(line);
	pcap_file_save = "/data/usbmon_finished" + line + ".pcap";
	inputFile.close();
	num++;
	std::ofstream outputFile("/root/.pcap_file_save");
	outputFile << num << std::endl;
	outputFile.close();

	return pcap_file_save;

}
size_t get_filesize(const char* file_name) {
	if (file_name == NULL)
		return 0;
	struct stat statbuf;
	stat(file_name, &statbuf);
	if (S_ISREG(statbuf.st_mode)) { //file exist
        // Get the file size from the stat structure
        return statbuf.st_size;
    } else {
        return 0;
    }

} 
void *pcap_file_max_and_resave(void *arg __attribute__((unused))) {
	std::string pcap_file_name = pcap_file();
	size_t pcap_filesize;
	while (true) {
		usleep(2000000);
		pcap_filesize = get_filesize(pcap_file_name.c_str());
		if (pcap_filesize > 1024000) {
			{
				std::lock_guard<std::mutex> lock(pcap_mtx);
				std::string pcap_file_save_name = pcap_file_save();
				printf("pcap is large 1M, size is %d resave new file\n", pcap_filesize);
				stop_tcpdump_usbmon(pcap_pid, pcap_file_name, pcap_file_save_name);
				pcap_pid = start_tcpdump_usbmon(bus_id, pcap_file_name);
			}
		}
	}
}
