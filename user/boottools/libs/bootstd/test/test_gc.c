/*
 * test_gc.c
 *
 * Copyright (c) 2006  Arcturus Networks Inc.
 *	by Oleksandr G Zhadan <www.ArcturusNetworks.com>
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
#include <stdio.h>
#include <errno.h>
#include <bootstd.h>

int main(int argc, char *argv[]) 
{
    int size;
    size = bsc_gc();
    printf("%s: %d bytes are available for enviroments after gabage collection\n", argv[0], size);
    return(0); 
}
