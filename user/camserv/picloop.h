#ifndef PICLOOP_DOT_H
#define PICLOOP_DOT_H

#include "camconfig.h"
#include "video.h"
#include "socket.h"
#include "filter.h"

extern int picture_taker( char *picture_memory,
			  int amt_alloced,
			  CamConfig *camconfig,
			  Socket *servsock );
extern int picture_single( CamConfig *ccfg, const char *fname, int psnaps );

#endif
