#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(14307);
  script_version ("$Revision: 1.11 $"); 

  script_bugtraq_id(10666);

  name["english"] = "BasiliX Content-Type XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a 
cross site scripting issue.

Description :

The remote host appears to be running BasiliX version 1.1.1 or lower. 
Such versions are vulnerable to a cross-scripting attack whereby an
attacker may be able to cause a victim to unknowingly run arbitrary
Javascript code simply by reading a MIME message with a specially
crafted Content-Type header. 

Solution : 

Upgrade to BasiliX version 1.1.1 fix1 or later.

See also : 

http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Content-Type XSS vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  script_dependencie("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.0.*|1\.1\.(0|1))$") {
    security_note(port);
    exit(0);
  }
}
