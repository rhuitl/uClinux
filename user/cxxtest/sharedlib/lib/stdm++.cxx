#include "stdm++"


MATT::CFile::CFile(FILE *file) 
{
	f = file;

	a_value = 100;
	value = 19;

	buf = new char[100];

	if (!buf) {
		fprintf(stderr, "Couldn't create buff\n");
	} else {
		fprintf(stderr, "A new buff created\n");
	}
}


MATT::CFile::~CFile()
{
	fprintf(stderr, "Destroying buffer\n");

	if (buf) {
		fprintf(stderr, "Buffer is being destroyed\n");
		delete [] buf;
	} else {
		fprintf(stderr, "Error - no buffer to destroy\n");
	}
}


int MATT::CFile::operator<< (char *string)
{
	fprintf(this->f, string);
	return 1;
}


MATT::CFile MATT::out(stdout);
