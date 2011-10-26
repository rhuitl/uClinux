#
# (C) Tenable Network Security
#


if (description) {
  script_id(17999);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1033");
  script_bugtraq_id(13050);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15315");
    script_xref(name:"OSVDB", value:"15316");
    script_xref(name:"OSVDB", value:"15317");
    script_xref(name:"OSVDB", value:"15318");
  }

  name["english"] = "CubeCart 2.0.6 and Earlier Multiple SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
SQL injection attacks. 

Description :

The installed version of CubeCart on the remote host suffers from
multiple SQL injection vulnerabilities due to its failure to sanitize
user input via the 'PHPSESSID' parameter of the 'index.php' script,
the 'product' parameter of the 'tellafriend.php' script, the 'add'
parameter of the 'view_cart.php' script, and the 'product' parameter
of the 'view_product.php' script.  An attacker can take advantage of
these flaws to manipulate database queries.

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-04/0083.html

Solution : 

Upgrade to CubeCart 2.0.7 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in CubeCart 2.0.6 and earlier";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# These exploits should just generate syntax errors.
exploits = make_list(
  "/index.php?PHPSESSID='",
  "/tellafriend.php?product='",
  "/view_cart.php?add='",
  "/view_product.php?product='"
);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see an error.
    if (egrep(string:res, pattern:"<b>Warning</b>: .+ in <b>.+\.php</b> on line")) {
      security_warning(port);
      exit(0);
    }
  }
}
