# -*- Fundamental -*-
#
# 
# (C) 2005 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# byte_func.inc
# $Revision: 1.2 $
#


BYTE_ORDER_BIG_ENDIAN  		= 1;
BYTE_ORDER_LITTLE_ENDIAN 	= 2;

ByteOrder = BYTE_ORDER_BIG_ENDIAN;

function set_byte_order()
{
 ByteOrder = _FCT_ANON_ARGS[0];
}

function mkbyte()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return raw_string(l & 0xff);
}

function mkword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
 	return  raw_string((l >> 8) & 0xFF, l & 0xFF);
 else
 	return  raw_string(l & 0xff, (l >> 8) & 0xff);
}


function mkdword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
	 return  raw_string( (l >> 24 ) & 0xff,
		     	     (l >> 16 ) & 0xff,
		     	     (l >>  8 ) & 0xff,
		     	     (l)   & 0xff);
 else
	 return  raw_string( l & 0xff,
		     	    (l >> 8) & 0xff,
		            (l >> 16) & 0xff,
		            (l >> 24)   & 0xff);
}


function getdword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 4 )
	return NULL;

 s = substr(blob, pos, pos + 3);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 24 | ord(s[1]) << 16 | ord(s[2]) << 8 | ord(s[3]);
 else
  return ord(s[0]) | ord(s[1]) << 8 | ord(s[2]) << 16 | ord(s[3]) << 24;
}

function getword(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 2 )
	return NULL;
 s = substr(blob, pos, pos + 1);
 if ( ByteOrder == BYTE_ORDER_BIG_ENDIAN )
  return ord(s[0]) << 8 | ord(s[1]);
 else
  return ord(s[0]) | ord(s[1]) << 8;
}

function getbyte(blob, pos)
{
 local_var l, s;
 if ( strlen(blob) < pos + 1 )
	return NULL;
 s = substr(blob, pos, pos);
 return ord(s[0]);
}




function mkpad()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return crap(data:raw_string(0), length:l);
}



