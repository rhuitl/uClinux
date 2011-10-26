/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "formats.h"
#include "netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>


void process_802_1x_auth(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type;
	seap;
	if (length < 3) {
		FRAMERR(frame, "802.1x: truncated\n");
		return;
	}

	switch (px[0]) {
	case 1: /*version = 1*/
		type = px[1];

		SAMPLE("IEEE802.11", "auth",REC_UNSIGNED, &type, sizeof(type));
		switch (type) {
		case 1: /*start*/
			break;
		case 3: /* KEY */
			break;
		default:
			FRAMERR(frame, "802.1x: truncated\n");
		}
		break;
	default:
		FRAMERR(frame, "802.1x: truncated\n");
		break;
	}
	
	
}

