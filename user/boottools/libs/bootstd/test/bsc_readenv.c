/*
 * bsc_readenv.c
 *
 * Copyright (c) 2006  Arcturus Networks Inc.
 *      by Mingqiang Wu <www.ArcturusNetworks.com>
 *
 * All rights reserved.
 *
 * This material is proprietary to Arcturus Networks Inc. and, in
 * addition to the above mentioned Copyright, may be subject to
 * protection under other intellectual property regimes, including
 * patents, trade secrets, designs and/or trademarks.
 *
 * Any use of this material for any purpose, except with an express
 * license from Arcturus Networks Inc. is strictly prohibited.
 *
 */


#include <string.h>
#include <stdio.h>
#include "bootstd.h"

int main(int argc, char *argv[])
{
        char varname[MAX_ENVNAME_SIZE+4], value[MAX_ENVDATA_SIZE+4];
        int i = 0;
        int p = 0;

        p = bsc_readenv(0, varname, sizeof(varname));
        while (p) {
                bsc_readenv(2, value, sizeof(value));
                printf("%s=%s\n", varname, value);
                i++;
                p = bsc_readenv(1, varname, sizeof(varname));
        }
        return(0);
}
