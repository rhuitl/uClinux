#include <stdio.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>

#define TEST_FILE "/etc/config/smgrd.xml"

int main(int argc, char *argv[])
{
	char buff[1024];
	std::ifstream ifs(TEST_FILE);

	bzero(buff, sizeof(buff));

	while (!ifs.fail()) {
		ifs.read(buff, sizeof(buff)-1);
		printf("--%s--\n", buff);
	}

	if (ifs.fail()) {
		if (!ifs.eof()) {
			std::cout << "Failed read file\n";
		} else {
			std::cout << "Read to file successfully\n";
		}
	}
}
