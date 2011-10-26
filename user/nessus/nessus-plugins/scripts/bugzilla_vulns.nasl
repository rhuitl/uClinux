#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11463);
 script_bugtraq_id(4964, 5842, 5843, 5844, 6257, 6501, 6502);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0012", "CVE-2003-0013", "CVE-2002-1198", "CVE-2002-1197", "CVE-2002-1196");
 

 name["english"] = "Bugzilla Multiple Flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Bugzilla bug tracking system, according to its
version number, is vulnerable to various flaws that may let
an attacker execute arbitrary commands on this host

Solution : Upgrade to 2.14.5, 2.16.2 or 2.17.3
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\.[0-4]|15\..*|16\.[0-1]|17\.[0-2]))[^0-9]*$",
       string:version))security_hole(port);
       
       
