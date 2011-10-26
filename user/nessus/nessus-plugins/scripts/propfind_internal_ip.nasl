#
# This script was written by Anthony R. Plastino III <tplastino@sses.net>
# Security Engineer with Sword & Shield Enterprise Security, Inc.
#
#

if(description)
{
  script_id(12113);
  script_version ("$Revision: 1.9 $");
  script_cve_id("CVE-2002-0422");
  name["english"] = "Private IP address Leaked using the PROPFIND method";
  script_name(english:name["english"]);

  desc["english"] = "
The remote web server leaks a private IP address through the WebDAV interface.  If this 
web server is behind a Network Address Translation (NAT) firewall or proxy server, then 
the internal IP addressing scheme has been leaked.

This is typical of IIS 5.0 installations that are not configured properly.

Detail: http://www.nextgenss.com/papers/iisrconfig.pdf 

Solution: see http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180
Risk factor : Low";

  script_description(english:desc["english"]);

  summary["english"] = "Checks for private IP addresses in PROPFIND response";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) Sword & Shield Enterprise Security, Inc., 2004");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# 
# Now the code
#

if ( egrep(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:string(get_host_ip()))) exit(0);

include("http_func.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

sig = get_http_banner(port:port);
if (!sig || "Microsoft-IIS" >!< sig) exit(0);


#
# Build the custome HTTP/1.1 request for the server to respond to
#

soc = http_open_socket(port);
if ( ! soc ) exit(0);
send(socket:soc, data:string("PROPFIND / HTTP/1.0\r\nHost:\r\nContent-Length: 0\r\n\r\n"));
headers = http_recv_headers2(socket:soc);
stuff = http_recv_body(socket:soc, headers:headers);
http_close_socket(soc);

# 
# now check for RFC 1918 addressing in the returned data - not necessarily in the header
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:stuff);
if(!isnull(private_ip) && private_ip[0] !~ "Oracle.*/10\.")
{
  report = string("
The remote web server leaks a private IP address through the WebDAV interface.
If this web server is behind a Network Address Translation (NAT) firewall or proxy 
server, then the internal IP addressing scheme has been leaked.
That address is: ", private_ip[0], "
This is typical of IIS 5.0 installations that are not configured properly.

See also : http://www.nextgenss.com/papers/iisrconfig.pdf
Solution : http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180
Risk factor : Low");

  security_note(port:port, data:report);
}
