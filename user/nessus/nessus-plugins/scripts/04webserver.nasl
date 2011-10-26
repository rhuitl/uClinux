#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15713);
 script_cve_id("CVE-2004-1512", "CVE-2004-1513", "CVE-2004-1514");
 script_bugtraq_id(11652);
 script_version("$Revision: 1.4 $");
 name["english"] = "04WebServer Multiple Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of 04WebServer which is older or as old
as version 1.42.

The remote version of this software is vulnerable to cross-site scripting
and log injection vulnerabilities wich may allow an attacker to do
cross-site scripting attacks.

Solution : Upgrade to version 1.5 of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of 04WebServer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: 04WebServer/(0\.|1\.([0-9][^0-9]|[0-3][0-9]|4[0-2]))", string:serv))
 {
   security_warning(port);
 }
