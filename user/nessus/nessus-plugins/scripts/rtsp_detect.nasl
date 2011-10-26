#
# (C) Tenable Network Security
#
#
#
# Thanks to Sullo for testing this plugin.
#

 desc["english"] = "
Synopsis :

A RTSP (Real Time Streaming Protocol) server is listening on the
remote port. 

Description :

The remote server is a RTSP server.  RTSP is a client-server
multimedia presentation protocol, which is used to stream videos and
audio files over an IP network. 

It is usually possible to obtain the list of capabilities and the
server name of the remote RTSP server by sending an OPTIONS request. 

See also :

http://www.rtsp.org/

Solution :

Disable this service if you do not use it. 

Risk factor : 

None";

if(description)
{
 script_id(10762);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "RTSP Server type and version";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "RTSP Server detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/rstp");
if ( ! port ) port = 554;

if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n');
 r = http_recv(socket:soc);
 if ( ! r ) exit(0);
 if ( ereg(pattern:"(RTSP/1\.[0-9] 200 OK|.* RTSP/1\.[0-9]$)", string:r) && egrep(pattern:"^CSeq:", string:r) )
 { 
   serv = egrep(pattern:"^Server:", string:r);
   if ( ! serv ) 
	{
	  via = egrep(pattern:"^Via: .*\(.*\)", string:r);
	  if ( via ) serv = ereg_replace(pattern:"^Via: .*\((.*)\).*", replace:"\1", string:via);
	}
   else
	serv -= "Server: ";

   report = desc["english"] + '\n\nPlugin output :\n\n';
   if ( serv ) report += 'Server Type : ' + serv + '\n\n';
   report += 'The remote RSTP header replies the following to the OPTIONS * method : \n\n' + r;
   security_note(port:port, data:report);
 }
}

