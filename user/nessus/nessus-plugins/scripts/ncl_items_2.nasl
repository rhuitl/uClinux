#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Reference:
# http://members.cox.net/ltlw0lf/printers.html
#

if(description)
{
 script_id(10665);
 script_bugtraq_id(2659);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0484");
 name["english"] = "tektronix's _ncl_items.shtml";
 name["francais"] = "tektronix's _ncl_items.shtml";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
The file /_ncl_items.shtml or /_ncl_subjects.shtml exists on the 
remote web server.
If the remote host is a Tektronix printer, then this page
allows anyone to reconfigure it without any authentication
means whatsoever.

An attacker may use this flaw to conduct a denial of service
attack against your business by preventing legitimate users
from printing their work, or against your network, by changing
the IP address of the printer so that it conflicts with the IP
address of your file server.

Solution : Contact Tektronix for a patch and filter incoming
traffic to this port
Risk factor : Low";
 


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of _ncl_*.shtml";
 summary["francais"] = "Vérifie la présence de _ncl_*.shtml";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

i = "/_ncl_items.shtml?SUBJECT=1";
if (is_cgi_installed_ka(port: port, item: i))
{
	if ( ! is_cgi_installed_ka(port: port, item: "/nessus"+rand()+".shtml?SUBJECT=1") )
	{
		security_warning(port);
		exit(0);
	}
}

if (is_cgi_installed_ka(port: port, item: "/_ncl_subjects.shtml"))
{
	if ( ! is_cgi_installed_ka(port: port, item: "/nessus"+rand()+".shtml?SUBJECT=1") ) security_warning(port);
}
