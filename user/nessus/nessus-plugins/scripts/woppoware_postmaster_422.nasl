#
# (C) Tenable Network Security
#


if (description) {
  script_id(18246);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1650", "CVE-2005-1651", "CVE-2005-1652", "CVE-2005-1653");
  script_bugtraq_id(13597);

  name["english"] = "Woppoware PostMaster <= 4.2.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote webmail service is affected by multiple flaws. 

Description :

According to its banner, the version of Woppoware Postmaster on the
remote host suffers from multiple vulnerabilities:

  - An Authentication Bypass Vulnerability
    An attacker can bypass authentication by supplying an
    account name to the 'email' parameter of the
    'message.htm' page. After this, the attacker can read
    existing messages, compose new messages, etc as the
    specified user.

  - Information Disclosure Vulnerabilities
    The application responds with different messages based
    on whether or not an entered username is valid. It 
    also fails to sanitize the 'wmm' parameter used in
    'message.htm', which could be exploited to conduct
    directory traversal attacks and retrieve arbitrary
    files from the remote host.

  - A Cross-Site Scripting Vulnerability
    The 'email' parameter of the 'message.htm' page is
    not sanitized of malicious input before use.

See also :

http://packetstormsecurity.nl/0505-exploits/postmaster.txt

Solution : 

Reconfigure Woppoware Postmaster, disabling the webmail service.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Woppoware PostMaster <= 4.2.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Woppoware.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: PostMaster" >!< banner) exit(0);
}


# Try to exploit the XSS flaw.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
req = http_get(
  item:string("/message.htm?email=", urlencode(str:xss)), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see our XSS.
if (
  "PostMaster Web Mail" >< res && 
  xss >< res
) {
  security_warning(port);
}
