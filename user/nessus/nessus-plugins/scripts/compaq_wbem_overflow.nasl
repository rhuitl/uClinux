#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(17997);
 script_bugtraq_id(12566);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Compaq WBEM Buffer Overflow Vulnerability";
 script_name(english:name["english"]);

desc["english"] = "
The remote host is running a Compaq Web Management server.

The remote version of this software is vulnerable to an unspecified
buffer overflow vulnerability which may allow an attacker to execute
arbitrary code on the remote host with the privileges of the
web server process.

Solution : Upgrade to version 5.96.0 of this software
See also : http://www.securityfocus.com/advisories/8087
Risk factor : High";
 
 script_description(english:desc["english"]);

 summary["english"] = "Compaq WBEM Server Version Check";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 2301);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
 
port = get_http_port(default:2301);
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner || "Server: CompaqHTTPServer/" >!< banner ) exit(0);

if ( egrep(pattern:"Server: CompaqHTTPServer/5\.([0-8][0-9]|9[0-4])", string:banner) )
	security_hole(port);
