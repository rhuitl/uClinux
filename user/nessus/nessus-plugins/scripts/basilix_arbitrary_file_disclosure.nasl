#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(14305);
  script_version ("$Revision: 1.11 $"); 

  script_cve_id("CVE-2002-1710");
  script_bugtraq_id(5062);

  name["english"] = "BasiliX Arbitrary File Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to information
disclosure. 

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. 
Such versions allow retrieval of arbitrary files that are accessible to
the web server user when sending a message since they accept a list of
attachment names from the client yet do not verify that the attachments
were in fact uploaded. 

Further, since these versions do not sanitize input to the 'login.php3'
script, it's possible for an attacker to establish a session on the
target without otherwise having access there by authenticating against
an IMAP server of his or her choosing. 

See also :

http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0113.html

Solution : 

Upgrade to BasiliX version 1.1.1 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary file disclosure vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.(0.*|1\.0))$") {
    security_warning(port);
    exit(0);
  }
}
