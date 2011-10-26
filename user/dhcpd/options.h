/* options.h */

unsigned char *getOption(unsigned char *options, int option_val);
int endOption(unsigned char **optionptr);
int addOption(unsigned char *optionptr, unsigned char code, char datalength, char *data);
int addOptionMulti(unsigned char *optionptr, unsigned char code, 
			char datalength, char *data,int mul);
int add_multiple_option(unsigned char *optionptr, unsigned char code, 
			char datalength, char *data1, char *data2, char *data3);

