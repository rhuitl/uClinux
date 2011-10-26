// $Id: parameters.h,v 1.8 2003/08/28 00:20:27 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifndef H_IPSENTINEL_PARAMETERS_H
#define H_IPSENTINEL_PARAMETERS_H


  //*******************
  //***
  //**  General parameters
  //*

  // ip-sentinel tries to ignore temporary errors when it has been daemonized.
  // How often an error occurs determines if it is of temporary nature or
  // not. MAX_ERRORS specifies the upper bound of allowed subsequent failures.
#define MAX_ERRORS		6u


  //*******************
  //***
  //**  Parameters affecting the random-MAC generation
  //*

  // The MAC which is used to create a random MAC from. To do this, the
  // RANDOM_MAC_OCTET'th octet (zero-based index), will be randomized.
#define RANDOM_MAC_BASE		{ 0xde, 0xad, 0xbe, 0xef, 0, 0 }
#define RANDOM_MAC_OCTET	5u

  // To be switch-friendly, only a limited amount of random MACs will be used
  // at a certain time. This amount is specified by BLACKLIST_RAND_COUNT
#define BLACKLIST_RAND_COUNT	32
  // The window of used random MACs will be rotated with increasing time.
  // BLACKLIST_RAND_PERIOD specifies the time in seconds after which a new
  // random MAC will be added to this window and an old one be removed.
#define BLACKLIST_RAND_PERIOD	30000


  //*******************
  //***
  //**  Parameters affecting the resizing of dynamic datastructures
  //*

  // When resizing of a vector is *necessarily*, the new allocated size will be
  // set to VECTOR_SET_THRESHOLD * count. Omitting of parentheses is intended
  // to allow rational numbers but to avoid floating point operations
#define VECTOR_SET_THRESHOLD	20/16
  // When resizing of a vector is *requested*, resizing will be done if
  // allocated size is more than VECTOR_DEC_THRESHOLD * count. This value must
  // be higher than VECTOR_SET_THRESHOLD.
#define VECTOR_DEC_THRESHOLD	24/16


  //*******************
  //***
  //**  Anti-DOS parameters
  //*

  // Limit the amount of pending arp-replies to MAX_REQUESTS count. When a new
  // job will be scheduled which is exceeding this count, the program will drop
  // it and sleep for a certain time.
#define MAX_REQUESTS		511u

  // DOS-measurement is given in a unit of connections per ANTIDOS_TIME_BASE
  // seconds
#define ANTIDOS_TIME_BASE	10

  // ARP-requests with DOS-values below LOW will be answered; between LOW and
  // HIGH the probability of an answer is decreasing linearly and requests over
  // HIGH will not be answered.
#define ANTIDOS_COUNT_LOW	20u
#define ANTIDOS_COUNT_HIGH	80u

  // Maximum DOS-values; this value is used to prevent overflows
#define ANTIDOS_COUNT_MAX	1000u

  // 
#define ANTIDOS_ENTRIES_MAX	0x8000


#endif	//  H_IPSENTINEL_PARAMETERS_H


  /// Local Variables:
  /// fill-column: 79
  /// End:
