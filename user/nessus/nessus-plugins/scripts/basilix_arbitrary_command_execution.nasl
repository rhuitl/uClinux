#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(14304);
  script_version ("$Revision: 1.8 $");
 
  script_bugtraq_id(3276);

  name["english"] = "BasiliX Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to arbitrary
command execution.

Description :

The remote host appears to be running a version of BasiliX between
1.0.2beta or 1.0.3beta.  In such versions, the script 'login.php3'
fails to sanitize user input, which enables a remote attacker to pass
in a specially crafted value for the parameter 'username' with
arbitrary commands to be executed on the target using the permissions
of the web server.

See also : 

http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2001-09/0017.html

Solution : 

Upgrade to BasiliX version 1.1.0 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary command execution vulnerability in BasiliX";
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

  if (ver =~ "^1\.0\.[23]") {
    security_hole(port);
    exit(0);
  }
}
