#
# (C) Tenable Network Security
#
  desc["english"] = "
Synopsis :

A X11 server is listening on the remote host

Description :

The remote host is running a X11 server. X11 is a client-server protocol
which can be used to display graphical applications running on a given
host on a remote client.

Since the X11 traffic is not ciphered, it is possible for an attacker
to eavesdrop on the connection. 

Solution :

Restrict access to this port. If the X11 client/server facility is not
used, disable TCP entirely.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:C)";


if(description)
{
  script_id(10407);
  script_version ("$Revision: 1.27 $");

  name["english"] = "X Server Detection";
  script_name(english:name["english"]);



 script_description(english:desc["english"]);

 summary["english"] = "X11 detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 exit(0);
}

include("misc_func.inc");


function x11_request(socket)
{
 local_var req, r, len;

 req = raw_string(
	0x6c,		# Little-Endian
	0x00,		# Unused
	0x0b, 0x00,	# Protocol Major Version
	0x00, 0x00,	# Protocol Minir Version
	0x00, 0x00,	# Authorization protocol name length
	0x00, 0x00,	# Authorization protocol data length
	0x00, 0x00);	# Unused


 send(socket:socket, data:req);
 
 r = recv(socket:socket, length:8);
 if ( strlen(r) != 8 ) return NULL;

 len = substr(r, 6, 7);
 len = ord(len[0]) + ord(len[1]) * 256;
 r += recv(socket:socket, length:len, min:len);
 if ( strlen(r) != len + 8 ) return NULL;
 return r;
}

function x11_open(blob)
{
 local_var ret;

 if ( ! blob ) return NULL;
 return ord(blob[0]);
}

function x11_version(blob)
{
 local_var ret, vers;

 if ( strlen(blob) <= 8 ) return NULL;
 vers = ord(blob[2]) + ord(blob[3]) * 256;
 ret = string(vers);
 vers = ord(blob[4]) + ord(blob[5]) * 256;
 ret += "." + vers;
 return ret;
}

function x11_release(blob)
{
 local_var ret;

 if ( strlen(blob) <= 11 ) return NULL;
 ret = substr(blob, 8, 11);
 ret = ord(ret[0]) + (ord(ret[1]) << 8) + (ord(ret[2]) << 16) + (ord(ret[3]) << 24);
 return ret;
}



function x11_vendor(blob)
{
 local_var len;

 if ( strlen(blob) < 25 ) return NULL;

 len = substr(blob, 24, 25);
 len = ord(len[0]) + ord(len[1]) * 256;
 if ( len >= strlen(blob) ) return NULL;
 return substr(blob, 40, 40 + len - 1);
}


function select(num, sockets, timeout)
{
 local_var flag, e, then, soc, i, ret;

 if ( ! defined_func("socket_ready") ) return sockets;

 then = unixtime();
 flag = 0;
 for ( i = 0 ; i < num ; i ++ ) ret[i] = 0;

 while ( TRUE )
 {
   flag = 0;
   for ( i = 0 ; i < num ; i ++ ) 
   {
    if ( sockets[i] != 0 )
	{
	 e = socket_ready(sockets[i]);
	 if ( e < 0 ) {
	 	close(sockets[i]);
		sockets[i] = 0;
		}
	 else if ( e > 0 ) {
	 	 ret[i] = sockets[i];
		 sockets[i] = 0;
		}
	 else flag ++;
	}
   }
   if ( unixtime() - then >= timeout ) return ret;
   if ( flag != 0 ) sleep(1);
   else break;
 }

 return ret;
}

for ( i = 0 ; i < 10 ; i ++ )
 {
  if ( get_port_state(6000 + i ) )
	{
	 if ( func_has_arg("open_sock_tcp", "nonblocking") )
  		sockets[i] = open_sock_tcp(6000 + i, nonblocking:TRUE);
	 else
  		sockets[i] = open_sock_tcp(6000 + i);
	}
  else
	sockets[i] = 0;
}


if ( NASL_LEVEL >= 3000 ) sockets = select(num:10, sockets:sockets, timeout:5);

for ( i = 0 ; i < 10 ; i ++ )
{
 soc = sockets[i];
 if ( soc != 0 )
 {
 report = NULL;
 blob = x11_request(socket:soc);
 close(soc);
 if ( ! blob ) continue;
 open = x11_open(blob:blob);
 version = x11_version(blob:blob);
 if ( open )
 {
  release = x11_release(blob:blob);
  vendor  = x11_vendor(blob:blob);
 }
 port = 6000 + i;
 if ( open == 1 ) set_kb_item(name:"x11/" + port + "/open", value:open);
 if ( version ) set_kb_item(name:"x11/" + port + "/version", value:version);
 if ( release ) set_kb_item(name:"x11/" + port + "/release", value:release);
 if ( vendor  ) set_kb_item(name:"x11/" + port + "/vendor", value:vendor);
 report = desc["english"] + '\n\nPlugin output :\n\n';
 report += 'X11 Version : ' + version + '\n';
 if ( open )
 {
  report += 'X11 Release : ' + release + '\n';
  report += 'X11 Vendor  : ' + vendor  + '\n';
 }
 security_note(port:port, data:report);
 register_service(port:port, proto:'x11');
 }
}

