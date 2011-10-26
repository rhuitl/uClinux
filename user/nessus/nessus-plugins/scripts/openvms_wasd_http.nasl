#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17150);
 script_cve_id("CVE-2002-1825");
 script_bugtraq_id(5811);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Multiple OpenVMS WASD HTTP Server Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running WASD HTTP server - a web server for the
OpenVMS platform.

The remote version of this software is vulnerable to various
vulnerabilities which may allow an attacker to execute arbitrary
code on the remote host.

Solution : Upgrade to OpenVMS WASD 7.2.4, 8.0.1 or 8.1
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the version of the remote HTTP Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( egrep(pattern:"^Server: HTTPd-WASD/([0-6]\.|7\.[01]\.|7\.2\.[0-3][^0-9]|8\.0\.0)", string:banner) )
	security_hole(port);
