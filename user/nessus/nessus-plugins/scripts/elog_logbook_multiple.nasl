#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16469);
 script_cve_id("CVE-2005-0439", "CVE-2005-0440");
 script_bugtraq_id(12556, 12639, 12640);
 script_version("$Revision: 1.6 $");

 name["english"] = "ELOG Web Logbook Multiple Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ELOG Web Logbook, a free webinterface logbook.

The remote version of this software is prone to a a buffer overflow 
vulnerability as well as an information disclosure vulnerability. 

An attacker may exploit this feature to obtain more information about the
set up of the remote host or to execute arbitrary commands with the privileges
of the web server.

Solution : Upgrade to version 2.5.7 or later.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of ELOG Web Logbook";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/?cmd=Config", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"^<center><a class=.*Goto ELOG home page.*midas\.psi\.ch/elog/.*ELOG V([0-1]\.|2\.([0-4]\.|5\.[0-6][^0-9]))", string:res) ) 
 {
        security_hole(port);
        exit(0);
 }
}

check(url:"/elog");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
