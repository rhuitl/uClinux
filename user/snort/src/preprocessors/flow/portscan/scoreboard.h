/**
 * @file   scoreboard.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu Jun  5 09:46:58 2003
 * 
 * @brief  implementation of a autorecovery scoreboard
 * 
 * Right now, there are two tables and memory is shared between them
 * both.  In the future, they should really share the same memory pool
 * and the free lists should have some method for figuring out which
 * one a node belongs in.
 *
 * @todo add a list of the last nodes I've talked to
 */

#ifndef _SCOREBOARD_H
#define _SCOREBOARD_H

#include "flowps.h"
#include "sfxhash.h"



#define PSENTRY_NEW     0x0001
#define PSENTRY_SLIDING 0x0002

/**
 * this is the data for an individual tracker
 *
 * currenly, all score board items have a score and 2 time's that may
 * be used for the time scale.
 */


int scoreboard_init(SCOREBOARD *sbp,
                    char *description,
                    TRACKER_POSITION kind,
                    unsigned int rows,  int memcap);

int scoreboard_destroy(SCOREBOARD *sbp);
int scoreboard_add(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp);
int scoreboard_find(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp);
int scoreboard_remove(SCOREBOARD *sbp, u_int32_t *address);

int scoreboard_move(SCOREBOARD *dst, SCOREBOARD *src, u_int32_t *address);

int scoreboard_memcap(SCOREBOARD *sbp);
int scoreboard_row_count(SCOREBOARD *sbp);
int scoreboard_overhead_bytes(SCOREBOARD *sbp);
void scoreboard_stats(SCOREBOARD *sbp, int dumpall);

#endif /* _SCOREBOARD_H */
