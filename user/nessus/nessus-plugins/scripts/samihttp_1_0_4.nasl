#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Based on Apache < 1.3.27 written by Renaud Deraison <deraison@cvs.nessus.org>
#

if(description)
{
 script_id(12073);
 script_cve_id("CVE-2004-0292");
 script_bugtraq_id(9679);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Sami HTTP Server v1.0.4";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running Sami HTTP Server v1.0.4 or older.

A vulnerability has been reported for Sami HTTP server v1.0.4.
An attacker may be capable of corrupting data such as return address,
and thereby control the execution flow of the program.
This may result in denial of service or execution of arbitrary code.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive

Solution : Upgrade Sami HTTP when an upgrade becomes available.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Sami HTTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
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
banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);

if ( egrep(pattern:"Server:.*Sami HTTP Server v(0\.|1\.0\.[0-4][^0-9])", string:banner) ) 
 {
   security_warning(port);
 }
}
