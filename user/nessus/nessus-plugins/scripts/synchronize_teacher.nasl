#
#
# This script is (C) Tenable Network Security
#
#

 desc["english"] = "
Synopsis :

A remote control software is running on the remote host.

Description :

The remote host is running SMART Technologies SynchronEyes Teacher.
This software allows teacher to remotely control student desktops.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";

if (description)
{
 script_id(21218);
 script_version ("$Revision: 1.2 $");
 script_name(english:"SynchronEyes Teacher detection");
 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running SynchronEyes Teacher");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 script_require_ports (5461);
 exit(0);
}


include("byte_func.inc");
 
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

function put_string (s)
{
 local_var i, tmp, len;

 len = strlen(s);
 tmp = mkdword (len);

 for (i=0; i<len; i++)
   tmp += mkbyte (0) + s[i];

 return tmp;
}


function getstring (blob, pos)
{
 local_var tmp, len, i, ret;

 if (strlen(blob) < (pos+4))
   return NULL;

 len = getdword (blob:blob, pos:pos);
 if (strlen(blob) < (pos+4+(len*2)))
   return NULL;
 
 pos += 4;
 tmp = NULL;

 for (i=0; i<len; i++)
   tmp += blob[pos+i*2+1];

 return tmp;
}


function parse_packet (format, data)
{
 local_var len, pos, tmp, ret, i;

 len = strlen (data);
 ret = NULL;
 pos = 0;

 for (i=0; i<max_index(format); i++)
 {
  if (format[i] == 0)
  {
   if (len < (pos+4))
     return NULL;

   ret[i] = getdword (blob:data, pos:pos);
   pos += 4;
  }
  else if (format[i] == 2)
  {
   if (len < (pos+2))
     return NULL;

   ret[i] = getword (blob:data, pos:pos);
   pos += 2;
  }
  else if (format[i] == 1)
  {
   tmp = getstring (blob:data, pos:pos);
   if (isnull(tmp))
     return NULL;

   pos += strlen(tmp) * 2;
   ret[i] = tmp;
  }
 }

 return ret;
}

function recv_sync_pkt (socket)
{
 local_var buf, len;

 buf = recv (socket:socket, length:8, min:8);
 if (strlen(buf) != 8)
   return NULL;

 len = getdword (blob:buf, pos:0);

 buf = recv (socket:socket, length:len, min:len);
 if (strlen(buf) != len)
   return NULL;

 return buf;
}


function send_sync_pkt (data)
{
 send (socket:soc, data:mkdword (strlen(data)) + mkdword (0) + data);
}


port = 5461;
#port = 5485;

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

data = mkdword (0) + 
       mkdword (0) + 
       put_string (s:"ConnectionEstablishementEB802D36-7E45-4757-BABA-84C75016AD3A") + 
       mkdword (2) + 
       mkword (6) + 
       mkword (0) + 
       mkword (30) + 
       mkword (1) + 
       mkdword (0);

send_sync_pkt (data:data);

buf = recv_sync_pkt (socket:soc);
if (isnull(buf))
  exit (0);

ret = parse_packet (data:buf, format:make_list (0,0,1,0,0,0));
if (isnull(ret))
  exit (0);

if ("ConnectionEstablishement" >!<ret[2])
 exit (0);

buf = recv_sync_pkt (socket:soc);
if (isnull(buf))
  exit (0);

ret = parse_packet (data:buf, format:make_list (0,0,1,0,0,0,0,2,2,2,2,1,0));
if (isnull(ret))
  exit (0);

if ("ScreenGrabberMsgCategory" >!< ret[2])
  exit (0);

version = string (ret[7],".",ret[8],".",ret[9],".",ret[10]);

report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote host is running SynchronEyes Teacher version ", version , "\n");

security_note(data:report, port:port);
