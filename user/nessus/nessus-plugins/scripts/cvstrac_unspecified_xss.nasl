#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16000);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(12017);
 script_cve_id("CVE-2004-1146");
 name["english"] = "CVSTrac Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running cvstrac, a web-based bug and patch-set 
tracking system for CVS.

This version of CVSTRAC is vulnerable to a cross-site scripting flaw which
may allow an attacker to use the remote server to perform attacks against
third party users of the remote service

Solution : Update to version 1.1.5 or disable this CGI suite
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for CVSTrac version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^(0\..*|1\.0\.|1\.1\.[0-4]([^0-9]|$))", string:version))
 		security_warning(port);
