#
# (C) Tenable Network Security
#


if (description) {
  script_id(19227);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2252", "CVE-2005-2253", "CVE-2005-2254", "CVE-2005-2255");
  script_bugtraq_id(14184);

  name["english"] = "Phpauction <= 2.5 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running Phpauction or one of its affiliate
versions, such as Web2035 Auction.  Phpauction is a web-based auction
system written in PHP. 

The version of Phpauction on the remote host suffers from multiple
flaws :

  - Remote Code Execution
    An attacker can control the 'lan' variable used to 
    include PHP code in the 'index.php' and 'admin/index.php'
    scripts, which _may_ allow him to view arbitrary files 
    on the remote host and execute arbitrary PHP code, 
    possibly even taken from third-party hosts.

  - Authentication Bypass
    By setting the cookie 'PHPAUCTION_RM_ID' to the id of an
    existing user, an attacker can bypass authentication.

  - SQL Injection
    The application does not properly sanitize user-supplied
    input to the 'category' parameter of the 'adsearch.php'
    script before using it in database queries.

  - Multiple Cross-Site Scripting Flaws
    The application fails to sanitize user-supplied input
    to several scripts before using it in dynamically-
    generated pages, which allows for cross-site scripting 
    attacks.

See also : 

http://securitytracker.com/alerts/2005/Jul/1014423.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Phpauction <= 2.5";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the XSS flaws.
  req = http_get(item:string(dir, "/index.php?lan=", exss), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get our XSS back as part of a PHP error message.
  if (string("/includes/messages.", xss, ".inc.php): failed to open stream") >< res) {
    security_warning(port);
    exit(0);
  }
}
