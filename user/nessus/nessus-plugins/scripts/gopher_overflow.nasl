#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16195);
 script_bugtraq_id(8157, 12254);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Gopherd Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the UMN Gopher server.

The remote version of the remote gopher server seems to be vulnerable
to various buffer overflows which may be exploited by an attacker to 
execute arbitrary code on the remote host with the privileges of the
gopher daemon.

Solution : Upgrade to UMN Gopherd 3.0.6 or newer
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if gopherd can be used as a proxy"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "Gain a shell remotely"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/gopher",70);
 exit(0);
}


include('http_func.inc');
port = get_kb_item("Services/gopher");
if ( ! port ) port = 70;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'GET / HTTP/1.0\r\n\r\n');
buf = http_recv_headers2(socket:soc);
close(soc);
if ( strlen(buf) && "GopherWEB" >< buf)
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'g\t+' + crap(63) + '\t1\nnessus\n');
 r = recv(socket:soc, length:65535);
 if ( ! r ) exit(0);
 close(soc);

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:'g\t+' + crap(70) + '\t1\nnessus\n');
 r = recv(socket:soc, length:65535);
 if ( ! r ) security_hole(port);
}

