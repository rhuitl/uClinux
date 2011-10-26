#
# (C) Tenable Network Security
#


if(description)
{
 script_id(12071);
 script_cve_id("CVE-2004-2274");
 script_bugtraq_id(9711);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"4014");
 }
 script_version("$Revision: 1.5 $");
 name["english"] = "JigSaw < 2.2.4";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of the JigSaw web server 
which is older than 2.2.4.

This version is vulnerable to a bug in the way it parses URIs.

An attacker might exploit this flaw to execute arbitrary code on this host.

Solution : Upgrade to version 2.2.4 or later.
See also : http://jigsaw.w3.org/
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of JigSaw";
 
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
 
if(egrep(pattern:"^Server: Jigsaw/([01]\.|2\.([01]\.|2\.[0-3][^0-9])).*", string:banner))
 {
   security_hole(port);
 }
