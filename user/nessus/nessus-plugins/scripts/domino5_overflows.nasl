#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(11338);
 script_bugtraq_id(3041, 7038, 7039);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0123", "CVE-2001-1311");

 name["english"] = "Lotus Domino Vulnerabilities";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote Lotus Domino server, according to its version number,
is vulnerable to various buffer overflows affecting it when
it acts as a client (through webretriever) or in LDAP.

An attacker may use these to disable this server or
execute arbitrary commands on the remote host.
	

References :
    http://www.rapid7.com/advisories/R7-0011.html
    http://www.rapid7.com/advisories/R7-0012.html

Solution : Update to Domino 5.0.12 or 6.0.1
Risk factor : High";	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote Domino Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);


if(egrep(pattern:"^Server: Lotus-Domino/(Release-)?(4\..*|5\.0.?([0-9]|1[0-1])[^0-9])", string:banner))security_hole(port);
