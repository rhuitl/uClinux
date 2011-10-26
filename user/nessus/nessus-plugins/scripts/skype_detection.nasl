#
# Copyright (C) 2005 Tenable Network Security
#
if(description)
{
 script_id(19772);
 script_version("$Revision: 1.5 $");

 name["english"] = "Skype detection";

 script_name(english:name["english"]);


 desc["english"] = "
Synopsis :

A Voice Over IP service is running on the remote port.

Description :

The remote host is running Skype, a peer-to-peer Voice Over IP application.

Due to the peer-to-peer nature of Skype, any user connecting to the Skype 
network may consume a large amount of bandwith.

Make sure the use of this program is done in accordance with your corporate
security policy.

Solution :

If this service is not needed, disable it. Note that filtering this port will
not be sufficient, since this software can establish outgoing connections.


Risk factor : 

None";



 script_description(english:desc["english"]);

 summary["english"] = "Skype detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Service detection");

 script_dependencie("find_service.nes", "embedded_web_server_detect.nasl");
 exit(0);
}


# start script
include("misc_func.inc");


port = get_kb_item("Services/www");
if ( ! port ) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
skype_hello  = raw_string(0xec, 0x42, 0x55, 0xa8, 
		    0xfb, 0x05, 0x58, 0x29, 
		    0x32, 0xcf, 0x0d, 0x0a, 
		    0x0d, 0x0a);

send(socket:soc, data:skype_hello);
r = recv(socket:soc, length:4096);
if ( ! r || strlen(r) < 14 ) exit(0);

close(soc);

e = 0;
for ( i = 0 ; i < 14 ; i ++ )
 if ( ord(r[i]) < ord("!") || ord(r[i]) > ord("~") ) e ++;

if ( e >= 3 )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:skype_hello);
 r2 = recv(socket:soc, length:4096);
 if ( r2 != r ) {
	security_note(port);
	register_service(port:port, proto:"skype");
	}
}
