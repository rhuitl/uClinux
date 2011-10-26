#
# (C) Tenable Network Security
#


if(description) {
  script_id(17202);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-0477");
  script_bugtraq_id(12607);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14004");
    script_xref(name:"OSVDB", value:"14005");
  }

  name["english"] = "Invision Power Board COLOR SML Tag Script Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack. 

Description :

According to the version number in its banner, the installation of
Invision Power Board on the remote host reportedly does not
sufficiently sanitize the 'COLOR' SML tag.  A remote attacker may
exploit this vulnerability by adding a specially-crafted 'COLOR' tag
with arbitrary Javascript to any signature or post on an Invision
board.  That Javascript will later be executed in the context of users
browsing that forum, which may enable an attacker to steal cookies or
misrepresent site content. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-02/0257.html
http://forums.invisionpower.com/index.php?showtopic=160633

Solution : 

Apply the patch referenced in the vendor advisory above.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:H/Au:R/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board COLOR SML Tag Script Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


# nb: don't run unless we're being paranoid since the solution is a patch.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.([12]\.|3\.[01])|2\.0\.[0-3])") security_note(port);
}
