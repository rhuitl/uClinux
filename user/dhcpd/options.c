/* options.c -- DHCP server option packet tools */

#include <stdio.h>


/* add new option data to the options field terminating
 * with an 0xff */
int addOption(unsigned char *optionptr, unsigned char code,
                                char datalength, char *data) {
        endOption(&optionptr);
        optionptr[0] = code;
        if(code == 0xff)
                return 0;
        optionptr++;
        optionptr[0] = datalength;
        optionptr++;
        memcpy(optionptr, data, datalength);
        optionptr += datalength;
        optionptr[0] = 0xff;
        return 0;
}


int add_multiple_option(unsigned char *optionptr, unsigned char code,
                                char datalength, char *data1, char *data2, char *data3) {
        endOption(&optionptr);
        optionptr[0] = code;
        if(code == 0xff)
                return 0;
        optionptr++;
        optionptr[0] = datalength;
        optionptr++;

        if(data1 != NULL) {
                memcpy(optionptr, data1, 0x04);
                optionptr += 0x04;
                if(data2 != NULL) {
                        memcpy(optionptr, data2, 0x04);
                        optionptr += 0x04;
                        if(data3 != NULL) {
                                memcpy(optionptr, data3, 0x04);
                                optionptr += 0x04;
                        }
                }
        }
        optionptr[0] = 0xff;
        return 0;
}


int addOptionMulti(unsigned char *optionptr, unsigned char code,
                                char datalength, char *data,int mul) {
        int i;

        endOption(&optionptr);
        optionptr[0] = code;
        if(code == 0xff)
                return 0;
        optionptr++;
        optionptr[0] = (datalength * mul);
        optionptr++;
        for (i=0;i<mul;i++) {
                memcpy(optionptr, data, datalength);
                optionptr += datalength;
        }
        optionptr[0] = 0xff;
        return 0;
}


/* update the option pointer to point to where the 0xff is */
int endOption(unsigned char **optionptr) {
        unsigned char *tmpptr = *optionptr;

        while(tmpptr[0] != 0xff) {
                if(tmpptr[0] == 0x00)
                        continue;
                tmpptr++;
                tmpptr += tmpptr[0];
                tmpptr++;
        }
        *optionptr = tmpptr;
        return 0;
}


unsigned char *getOption(unsigned char *options, int option_val) {
        while(options[0] != 0xff) {
                if(options[0] == 0) {
                        options++;
                        continue;
                }
                if(options[0] == 0xff)
                        return NULL;
                if(options[0] == option_val)
                        return options+2;
                options++;
                options += options[0];
                options++;
        }
        return NULL; /* never executed */
}
