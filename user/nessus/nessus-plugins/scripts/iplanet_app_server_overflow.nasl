#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
#
# This plugin is (C) Renaud Deraison
#
# Ref:
# Date: Thu, 13 Mar 2003 11:48:17 -0500
# From: "@stake Advisories" <advisories@atstake.com>
# To: bugtraq@securityfocus.com
# Subject: Sun ONE (iPlanet) Application Server Connector Module Overflow


if(description)
{
 script_id(11403);
 script_bugtraq_id(7082);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0387");
 
 name["english"] = "iPlanet Application Server Buffer Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Sun ONE Application Server (formerly known as iPlanet Application
Server) is vulnerable to a buffer overflow when a user
provides a long buffer after the application service prefix, as in

	GET /[AppServerPrefix]/[long buffer]
	
An attacker may use this flaw to execute arbitrary code on this
host or disable it remotely.

Solution : If you are running Application Server 6.5, apply SP1. There is
no patch for 6.0 users
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Sun ONE AS SP1 is applied";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "iplanet_app_server_detection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

d = get_kb_item(string("www/", port, "/SunOneApplicationServer/prefix"));
if( d == NULL ) d = "/NASApp";


req = http_get(item:string(d,"/nessus/"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

#
# Post-SP1 replies with a "200 OK" error code, followed by
# an error saying 'GX Error (GX2GX) (blah blah)'
#
if(("ERROR: Unknown Type of Request" >< res))
{
 security_hole(port);
 exit(0);
}

