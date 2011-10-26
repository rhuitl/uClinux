#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(20747);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(16226);
 script_cve_id("CVE-2005-3655");
 script_xref(name:"OSVDB", value:"22455");

 name["english"] = "SuSE Open Enterprise Server Novell Remote Manager HTTP Request Header Heap Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote web server.

Description :

The remote host is running Novell Remote Manager HTTP service
for SuSE Enterprise or Open Enterprise Server.
The remote version of this software is vulnerable to a heap overflow
vulnerability which may be exploited by sending a negative value for
the 'Content-Length' field.

Since the 'httpstkd' service runs with the root privileges, an
attacker can gain full control of the remote host.

Solution :

Novell has released a patch for the novell-nrm service :
http://www.novell.com/linux/security/advisories/2006_02_novellnrm.html

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Novel Remort Manager HTTP Heap Overflow";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8008, 8009);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8008);
if (!get_port_state (port))
  exit (0);

banner = get_http_banner (port:port);

if ("NetWare HTTP Stack" >!< banner)
  exit (0);

req = string ("POST / HTTP/1.0\r\n",
              "Content-Length: -2147483648\r\n\r\n");

rep = http_keepalive_send_recv(port:port, data:req);


# patched version replies with "HTTP/1.1 400 Bad request"

if (rep && ("HTTP/1.1 500 Malfunction" >< rep))
  security_warning(port);

