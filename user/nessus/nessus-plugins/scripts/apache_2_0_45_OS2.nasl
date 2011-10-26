#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Wed, 2 Apr 2003 09:38:28 +0200
#  From: Lars Eilebrecht <lars@apache.org>
#  To: bugtraq@securityfocus.com
#  Subject: [ANNOUNCE] Apache 2.0.45 Released


if(description)
{
 script_id(11607);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0012");
 script_bugtraq_id(7332);
 script_cve_id("CVE-2003-0134");

 script_version("$Revision: 1.6 $");
 
 name["english"] = "Apache < 2.0.46 on OS/2";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of
Apache 2.x which is older than 2.0.46 on OS/2

There is a OS/2 specific bug in this version which
may allow an attacker to disable this service remotely
by abusing a flaw in the filestat.c code which is
OS2-specific.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

Solution : Upgrade to version 2.0.46 when available
See also : http://www.apache.org/dist/httpd/CHANGES_2.0
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-5]) .OS/2.", string:serv))
 {
   security_warning(port);
 }
}
