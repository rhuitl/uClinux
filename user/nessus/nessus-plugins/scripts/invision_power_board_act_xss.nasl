#
# (C) Tenable Network Security
#


if (description) {
  script_id(18201);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1443");
  script_bugtraq_id(13483);

  name["english"] = "Invision Power Board act Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-site
scripting attacks. 

Description :

The version of Invision Power Board installed on the remote host suffers
from a cross-site scripting vulnerability due to its failure to sanitize
user input via the 'act' parameter to the 'index.php' script.  An
unauthenticated attacker can exploit this flaw by injecting malicious
HTML and script code through the nickname field to redirect forum
visitors to arbitrary sites, steal authentication cookies, and the like. 

See also :

http://www.governmentsecurity.org/forum/index.php?act=ST&f=26&t=14656

Solution : 

Upgrade to Invision Power Board 2.0.4 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for act parameter cross-site scripting vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit it.
  req = http_get(item:string(dir, "/index.php?act=", exss), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (xss >< res) security_note(port);
}
