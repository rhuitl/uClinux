#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Scott Dewey
#
#  This script is released under the GNU GPL v2
#

if (description) {
script_id(19584);
script_bugtraq_id(14726);
script_version("$Revision: 1.1 $");

name["english"] = "Phorum register.php Cross-Site Scripting";
script_name(english:name["english"]);

desc["english"] = "
The remote version of Phorum contains a script called 'register.php'
which is vulnerable to a cross-site scripting attack.  An attacker may
exploit this problem to steal the authentication credentials of third
party users. 

See also : http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0018.html
Solution : Upgrade to Phorum 5.0.18 or later.
Risk factor : Medium";
script_description(english:desc["english"]);

summary["english"] = "Checks for cross-site scripting vulnerability in Phorum's register.php";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");

family["english"] = "CGI abuses : XSS";
script_family(english:family["english"]);

script_dependencie("phorum_detect.nasl");
script_require_ports("Services/www", 80);

exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\..*|5\.0\.([0-9][^0-9]*|1[0-7][^0-9]*))$")
    security_warning(port);
}
