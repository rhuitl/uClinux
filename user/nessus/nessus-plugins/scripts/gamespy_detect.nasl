#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Details:  http://www.pivx.com/kristovich/poc/bf1942dos.c
#	    http://www.pivx.com/kristovich/adv/mk001/
#
#

if(description)
{
 script_id(11211);
 script_bugtraq_id(6636);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "GameSpy detection";

 script_name(english:name["english"]);

    desc["english"] = "
The remote host is running a GameSpy server.
 
This service is used to host a gaming server.

It turns out that since these server use UDP as their transport layer, an 
attacker may misuse them so that they flood a third party host, as they send 
multiple UDP packets in reply to one request, by sending a spoofed
UDP packet with the IP address of their target as the source field.


An attacker may use this service and network connection as a mean to flood a 
third party host.


Solution : Filter incoming traffic to this port, or disable this service
Risk factor : Medium
See also: http://www.pivx.com/kristovich/adv/mk001/";


 script_description(english:desc["english"]);
 

 summary["english"] = "Checks for the presence of a GameSpy server";
 
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 				francais:"Ce script est Copyright (C) 2003 Renaud Deraison");

 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

# There's <official port> to bind a gamespy server to, and
# scanning all the UDP ports would take too much time. We try
# a list of common ports instead.
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port[0] = 7777;
port[1] = 8888;
port[2] = 12203;
port[3] = 12204;
port[4] = 14567;
port[5] = 14570;
port[6] = 22000;
port[7] = 23000;
port[8] = 27015;
port[9] = 27016;
port[10] = 27960;
port[11] = 27961;
port[12] = 28001;
port[13] = 28002;
port[14] = 28016;
port[15] = 28020;
port[16] = 28040;
port[17] = 28672;

port[18] = 0;

for(i=0;port[i];i=i+1)
{
soc = open_sock_udp(port[i]);
if ( ! soc ) exit(0);
send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
r = recv(socket:soc, length:4096, timeout:2);
if(strlen(r) > 0)
 {
 if(("disconnect" >< r) ||
    (strlen(r) == 4 && ord(r[0]) == 0x00 && ord(r[1]) == 0x40))
    	{
	set_kb_item(name:"Services/udp/gamespy", value:port);
	security_note(port[i]);
	exit(0);
	}
 }
 close(soc);
}
