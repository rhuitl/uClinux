#
# (C) Tenable Network Security
#


if (description) {
  script_id(17634);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0896");
  script_bugtraq_id(12900);

  script_name(english:"PHPMyDirectory review.php Multiple Cross-Site Scripting Vulnerabilities");

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
multiple cross-site scripting attacks. 

Description :

The version of phpMyDirectory installed on the remote host suffers
from multiple cross-site scripting vulnerabilities due to its failure
to sanitize user-input to its 'review.php' script through various
parameters.  A remote attacker can exploit these flaws to steal
cookie-based authentication credentials and perform other such
attacks. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0432.html

Solution : 

Upgrade to phpMyDirectory version 10.1.6 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPMyDirectory's review.php");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
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
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);


# Check various directories for PHPMyDirectory.
foreach dir (cgi_dirs()) {
  # Try to exploit the vulnerability with our XSS.
  req = http_get(
    item:string(
      dir, "/review.php?",
      "id=1&",
      "cat=&",
      'subcat=%22%3E' , exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it's from phpMyDirectory and...
    ('<META name="copyright" CONTENT="Copyright, phpMyDirectory.com.' >< res) &&
    # we see our exploit.
    (xss >< res)
  ) {
    security_note(port);
    exit(0);
  }
}
