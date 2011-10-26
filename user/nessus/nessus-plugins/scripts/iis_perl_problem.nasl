#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# See:
# Date:  29 Dec 2001 18:53:39 -0000
# From: "antoan miroslavov" <shaltera@yahoo.com>
# To: bugtraq@securityfocus.com
# Subject: Active Perl path reveal
#

if(description)
{
 script_id(10120);
 script_bugtraq_id(194);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0450");
 name["english"] = "IIS perl.exe problem";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to obtain the physical location of a
virtual web directory of this host by issuing the command :

	GET /scripts/no-such-file.pl HTTP/1.0
	
An attacker may use this flaw to gain more information about the remote
host, and hence make more focused attacks.

Solution : Use perlis.dll instead of perl.exe.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to find the location of the remote web root";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);
if(get_port_state(port))
{
  d = http_get(item:"/scripts/no-such-file.pl", port:port);
  r = http_keepalive_send_recv(port:port, data:d);
  if ( ! r ) exit(0);
  r = tolower(r);
  if("perl script" >< r)security_warning(port);
}
