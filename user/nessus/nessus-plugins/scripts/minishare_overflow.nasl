#
# written by Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
#
# Changes by Tenable Network Security :
#
# * detect title to prevent false positives
# * fix version detection
# * added CVE and OSVDB xrefs.
#


if(description)
{
 script_id(18424);
 script_cve_id("CVE-2004-2271");
 script_bugtraq_id (11620);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11530");
 }
 script_version ("$Revision: 1.5 $");


 name["english"] = "MiniShare webserver buffer overflow";
 script_name(english:name["english"]);

 desc["english"] = "
MiniShare 1.4.1 and prior versions are affected by a buffer overflow flaw.
A remote attacker could execute arbitrary commands by sending a specially
crafted file name in a the GET request.

Version 1.3.4 and below do not seem to be vulnerable.

Solution: Upgrade to MiniShare 1.4.2 or higher.
Risk factor : High";
 script_description(english:desc["english"]);

 summary["english"] = "MiniShare webserver buffer overflows";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 SensePost");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if ("<title>MiniShare</title>" >!< res)
  exit (0);

if (egrep (string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[0-1][^0-9])'))
  security_hole (port);
}
