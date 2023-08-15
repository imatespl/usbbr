#include <math.h>
#include <bits/stdc++.h>

#include "misc.h"



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
	pcap_pid = child_pid;
	
}

int stop_tcpdump_usbmon(pid_t pcap_pid, std::string pcap_file, std::string pcap_file_save) {
	if (kill(pcap_pid, SIGTERM) != 0) {
		printf("Kill pcap process failed\n");
		return -1;
	}

	// Wait for the child process to finish
	int status;
	waitpid(pcap_pid, &status, 0);
	std::string save_command = "mv " + pcap_file + " " + pcap_file_save;
	system(save_command.c_str());
	return 0;
	
}

std::string pcap_file() {
	return "/home/ftpusb/usb_running.pcap";
}

std::string pcap_file_save() {
	std::string pcap_file_save;
	std::ifstream inputFile("/root/.pcap_file_save");

	std::string line;
	std::getline(inputFile, line);
	int num = std::stoi(line);
	pcap_file_save = "/home/ftpusb/usbmon_finished" + line + ".pcap";
	inputFile.close();
	num++;
	std::ofstream outputFile("/root/.pcap_file_save");
	outputFile << num << std::endl;
	outputFile.close();

	return pcap_file_save;

}
