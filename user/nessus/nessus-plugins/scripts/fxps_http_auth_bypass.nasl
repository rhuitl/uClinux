#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22272);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2113");
  script_bugtraq_id(19716);
  script_xref(name:"OSVDB", value:"28250");

  script_name(english:"Fuji Xerox Printing Systems Authentication Bypass Vulnerability");
  script_summary(english:"Gets version of remote printer");

  desc = "
Synopsis :

The remote web server is affected by an authentication bypass isssue. 

Description :

The remote host appears to be a Fuji Xerox Printing Systems (FXPS)
printer. 

According to its firmware version, the web server component of the
FXPS device reportedly fails to authenticate HTTP requests, which may
allow a remote attacker to gain administrative control of the affected
printer and make unauthorized changes to it, including denying service
to legitimate users. 

See also :

https://itso.iu.edu/20060824_FXPS_Print_Engine_Vulnerabilities
http://www.securityfocus.com/archive/1/444321/30/0/threaded

Solution :

Apply the appropriate patch as referenced in the advisory. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:N/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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


# Make sure it's one of the affected printers.
req = http_get(item:"/ews/index.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);
if ("Server: EWS-NIC" >!< res) exit(0);


# Figure out the model.
model = NULL;
pat = "<title>([^<]+)</title";
matches = egrep(pattern:pat, string:res);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    model = eregmatch(pattern:pat, string:match);
    if (!isnull(model)) {
      model = model[1];
      break;
    }
  }
}
if (isnull(model)) exit(0);


# And its firmware version.
req = http_get(item:"/ews/status/infomation.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

ver = NULL;
pat = "Firmware Version<.+>([0-9]+)</td";
matches = egrep(pattern:pat, string:res);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      ver = ver[1];
      break;
    }
  }
}
if (isnull(ver)) exit(0);


# There's a problem if...
if (
  # it's a Dell Laser printer with an affected firmware version.
  "Dell Laser Printer" >< model &&
  (
    # nb: version numbers come from COMMENT_BUILD header in the patched prn files.
    ("5110cn" >< model && int(substr(ver, 0, 7)) < 20060601) ||
    ("3110cn" >< model && int(substr(ver, 0, 7)) < 20060526) ||
    ("3010cn" >< model && int(substr(ver, 0, 7)) < 20060602) ||
    ("5100cn" >< model && int(substr(ver, 0, 7)) < 20060607) ||
    ("3100cn" >< model && int(substr(ver, 0, 7)) < 20060607) ||
    ("3000cn" >< model && int(substr(ver, 0, 7)) < 20060607)
  )
) security_warning(port);
