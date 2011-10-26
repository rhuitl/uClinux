/*
 * fsm.h - Finite state machine control.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

/* States for the control DFA */

#define STATE_DOWN 0
#define STATE_CONNECT 1
#define STATE_STOP_DIAL 2
#define STATE_KILL_DIAL 3
#define STATE_START_LINK 4
#define STATE_STOP_LINK 5
#define STATE_KILL_LINK 6
#define STATE_UP 7
#define STATE_DISCONNECT 8
#define STATE_CLOSE 9
#define STATE_RETRY 10
#define STATE_ERROR 11
#define STATE_ZOMBIE 12
#define STATE_HALF_DEAD 13
