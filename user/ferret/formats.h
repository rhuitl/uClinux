/* Copyright (c) 2007 by Errata Security */
#ifndef __FORMATS_H
#define __FORMATS_H


#define ex32be(px)  (	*((unsigned char*)(px)+0)<<24 \
					|	*((unsigned char*)(px)+1)<<16 \
					|	*((unsigned char*)(px)+2)<< 8 \
					|	*((unsigned char*)(px)+3)<< 0 )
#define ex32le(px)  (	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<<16 \
					|	*((unsigned char*)(px)+3)<<24 )
#define ex16be(px)  (	*((unsigned char*)(px)+0)<< 8 \
					|	*((unsigned char*)(px)+1)<< 0 )
#define ex16le(px)  (	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 )

#define ex24be(px)  (	*((unsigned char*)(px)+0)<<16 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<< 0 )
#define ex24le(px)  (	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<<16 )

#endif /*__FORMATS_H*/
