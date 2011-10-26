#
# (C) Tenable Network Security
#


if (description) {
  script_id(18138);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1315");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15764");

  name["english"] = "Turba common-footer.inc Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a cross-
site scripting attack. 

Description :

According to its version, the remote installation of Turba fails to
fully sanitize user-supplied input when setting the parent frame's
page title by javascript in 'templates/common-footer.inc'.  By
leveraging this flaw, an attacker may be able to inject arbitrary HTML
and script code into a user's browser to be executed in the context of
the affected web site, thereby resulting in the theft of session
cookies and similar attacks. 

See also :

http://lists.horde.org/archives/announce/2005/000200.html

Solution : 

Upgrade to Turba 1.2.5 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in Turba common-footer.inc";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("horde_turba_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde_turba"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0|1\.([01]|2$|2\.[0-4]([^0-9]|$)))") security_note(port);
}
