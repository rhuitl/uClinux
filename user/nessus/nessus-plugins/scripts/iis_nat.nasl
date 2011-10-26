#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#


 desc["english"] = "
Synopsis :

This web server leaks a private IP address through its HTTP headers.

Description :

This may expose internal IP addresses that are usually hidden or masked
behind a Network Address Translation (NAT) Firewall or proxy server.

There is a known issue with IIS 4.0 doing this in its default configuration.

See also :

http://support.microsoft.com/support/kb/articles/Q218/1/80.ASP
See the Bugtraq reference for a full discussion.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


if(description)
{
 script_id(10759);
 script_bugtraq_id(1499);
 script_cve_id("CVE-2000-0649");
 script_version ("$Revision: 1.21 $");
 name["english"] = "Private IP address leaked in HTTP headers";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "Checks for private IP addresses in HTTP headers";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");

if ( report_paranoia == 0 )
{
 if ( ! all_addr_public )  exit(0);
}
else if ( all_addr_private ) exit(0);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

#
# Craft our own HTTP/1.0 request for the server banner.
# Note: HTTP/1.1 is rarely useful for detecting this flaw.
#
soc = http_open_socket(port);
if(!soc) exit(0);
send(socket:soc, data:string("GET / HTTP/1.0\r\n\r\n"));
banner = http_recv_headers2(socket:soc);
http_close_socket(soc);

#
# Check for private IP addresses in the banner
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"([^12]10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:banner);
if(!isnull(private_ip) && ! egrep(pattern:"Oracle.*/10\.", string:banner) && (private_ip[0] != get_host_ip()) )
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"This web server leaks the following private IP address : ",
		private_ip[0]);

 security_note (port:port, data:report);
}
