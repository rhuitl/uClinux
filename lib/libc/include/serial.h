/* serial.h: Serial interface manipulation, and CRC generation
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#ifndef _SERIAL_H_
#define _SERIAL_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>

extern void make_raw_tty(struct termios * tty);
extern void make_cooked_tty(struct termios * tty);
extern int setserial(int fd, const char * modestring);

extern int getserialparams(int fd, int * baud, char * parity, int * dbits, int * sbits, char * modem, char * hs);
extern int setserialparams(int fd, int * baud, char * parity, int * dbits, int * sbits, char * modem, char * hs);

extern size_t readall(int fd, void * buf, size_t count, struct timeval * timeout);
extern size_t writeall(int fd, void * buf, size_t count, struct timeval * timeout);
extern size_t readaline(int fd, char * buf, size_t count, struct timeval * timeout);

extern int tcspeed_to_number(speed_t code);
extern speed_t tcspeed_from_number(int number);
extern int cfgetospeedn(struct termios *tp);
extern int cfgetispeedn(struct termios* tp);
extern int cfsetospeedn(struct termios *tp, int speed);
extern int cfsetispeedn(struct termios *tp, int speed);

extern int identify_485(int fd);
extern void commstatus(int error);
extern void alarmstatus(int alarm);

extern void printf_hexdump(unsigned char * buffer, int length, unsigned long pos);


/**	Add a byte to an arbitrary CRC accumulator.

	This macro adds its byte parameter to the given accumulator variable,
	using an arbitrary CRC calculation function (defined by the other parameters).
	
	The accumulator is used for for input and output. If you need to
	compute a CRC over a range of bytes, look at
	\Ref{BLOCK_ACCUMULATE_CRC}. Note that neither of these functions
	take care of initializing or finalizing the accumulator, and
	\Ref{COMPUTE_CRC} is better suited for normal CRC computation tasks.
	
	Note that any code using this macro should be compiled with some
	optimization enabled, so that the compiler will remove unnecessary
	code sections.
	
	This function iterates over each bit of the input data, and is not
	especially fast. For better performance, at the cost of code-size,
	look at \Ref{ACCUMULATE_CRC_TABLE} and its related macros.
	
	Please see \Ref{COMPUTE_CRC} for more information on the CRC parameters.
	
	@param accumulator	The name of a variable (ideally, of crc_type) to destructively use in
				CRC calculation.
	@param crc_type		A C integral type to be used for CRC calculations. 'unsigned char', 
				'unsigned short int', or 'unsigned int' are the only sensible values.
	@param polynomial	The determining polynomial, in zero-padded, upper-case hex. (Don't
				include the high bit of the polynomial: it should fit exactly in to
				crc_type.)
	@param reflect		An integer, 1 or 0, saying whether the calculations should be reversed.
				(Specifically, whether input bytes should be read from MSB-to-LSB or vice versa,
				{\it and} whether the accumulator will be inverted. Technically, split reflections,
				where the input is reflected and not the output, or vice versa, are possible,
				but are not supported.)
	@param byte		The byte of input to be added to the accumulator, CRC style.
 **/

#define ACCUMULATE_CRC(accumulator, crc_type, polynomial, reflect, byte)	\
({										\
	int _bit;								\
	if (reflect) {								\
		accumulator ^= (byte);						\
		for (_bit = 0; _bit < 8; _bit++) {				\
			if (accumulator & 0x0001)				\
				accumulator = (accumulator >> 1) ^ (polynomial);\
			else							\
				accumulator = (accumulator >> 1);		\
		}								\
	} else { 								\
		accumulator ^= (byte) << ( sizeof(crc_type)*8 -8);		\
		for (_bit = 0; _bit < 8; _bit++) {				\
			if (accumulator & (1<<( sizeof(crc_type)*8 -1)))	\
				accumulator = (accumulator << 1) ^ (polynomial);\
			else							\
				accumulator = (accumulator << 1);		\
		}								\
	}									\
})

/**	Add a byte to an table-based arbitrary CRC accumulator.

	Please see the documentation for \Ref{ACCUMULATE_CRC} for
	documentation, as it is called in an identical fashion to this
	macro.
	
	To use this macro, a special CRC table must be compiled into the
	serial library. Please look at the documentation for \Ref{gencrctable}
	for more information.
 **/

#define ACCUMULATE_CRC_TABLE(accumulator, crc_type, polynomial, reflect, byte)				\
({													\
	extern crc_type crc_ ## polynomial ## _ ## reflect [256];					\
	if (reflect) {											\
		accumulator = crc_ ## polynomial ## _ ## reflect					\
		[ ( accumulator ^ (byte)) & 0xFF ] ^ (accumulator >> 8);				\
	} else {											\
		accumulator = crc_ ## polynomial ## _ ## reflect					\
		[ ( ( accumulator >> (sizeof(crc_type)*8-8) ) ^ (byte)) & 0xFF] ^ (accumulator << 8);	\
	}												\
})

#define BLOCK_ACCUMULATE_CRC(accumulator, crc_type, polynomial, reflect, block, block_length)	\
({												\
	unsigned char * _data = (unsigned char *)block;						\
	while (block_length-- > 0)								\
		ACCUMULATE_CRC(accumulator, crc_type, polynomial, reflect, *_data++);		\
})

#define BLOCK_ACCUMULATE_CRC_TABLE(accumulator, crc_type, polynomial, reflect, block, block_length)	\
({													\
	unsigned char * _data = (unsigned char *)block;							\
	while (block_length-- > 0)									\
		ACCUMULATE_CRC_TABLE(accumulator, crc_type, polynomial, reflect, *_data++);		\
})

/** Compute an arbitrary CRC of a block of data.

	The parameters defining the CRC function (type, polynomial, and
	reflection) must match the desired algorithm to produce useful
	results. If a custom CRC is desired, these should {\em not} be set
	at random, as the result will probably be sub-optimal. (For more
	information on this topic, please see Tanenbaum, A.S., "Computer
	Networks", Prentice Hall, 1981, ISBN: 0-13-164699-0.)
	
	One common set of values (which is called by too many different names
	for them to be of any use in recognizing it): 
	
		0xFFFF, 0, unsigned short int, 0x1021, 0
	
	For a more efficent computation, please see \Ref{COMPUTE_CRC_TABLE}.

	@param init		The value to initialize the accumulator with.
	@param finish		The value to xor the accumulator with before returning it.
	@param crc_type		A C integral type to be used for CRC calculations. 'unsigned char', 
				'unsigned short int', or 'unsigned int' are the only sensible values.
	@param polynomial	The determining polynomial, in zero-padded, upper-case hex. (Don't
				include the high bit of the polynomial: it should fit exactly in to
				crc_type.)
	@param reflect		An integer, 1 or 0, saying whether the calculations should be reversed.
				(Specifically, whether input bytes should be read from MSB-to-LSB or vice versa,
				{\it and} whether the accumulator will be inverted. Technically, split reflections,
				where the input is reflected and not the output, or vice versa, are possible,
				but are not supported.)
	@param block		pointer to block of data to computer CRC over.
	@param block_length	number of bytes in the supplied block.

 **/

#define COMPUTE_CRC(init, finish, crc_type, polynomial, reflect, block, block_length)		\
({												\
	crc_type	accumulator = init;							\
	BLOCK_ACCUMULATE_CRC(accumulator, crc_type, polynomial, reflect, block, block_length);	\
	accumulator ^= finish;									\
	accumulator;										\
})

#define COMPUTE_CRC_TABLE(init, finish, crc_type, polynomial, reflect, block, block_length)		\
({													\
	crc_type	accumulator = init;								\
	BLOCK_ACCUMULATE_CRC_TABLE(accumulator, crc_type, polynomial, reflect, block, block_length);	\
	accumulator ^= finish;										\
	accumulator;											\
})

#endif /*_SERIAL_H_*/
