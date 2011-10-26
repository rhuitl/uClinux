#
# (C) Tenable Network Security
#


if (description) {
  script_id(18626);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2161");
  script_bugtraq_id(14151);

  name["english"] = "phpBB <= 2.0.16 Nested BBCode URL Tags Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application affected by a cross-
site scripting issue. 

Description :

According to its banner, the remote host is running a version of phpBB
that fails to sanitize BBCode containing nested URL tags, which
enables attackers to cause arbitrary HTML and script code to be
executed in a user's browser within the context of the affected site. 

See also : 

http://www.securityfocus.com/archive/1/404300/30/0/threaded

Solution : 

Upgrade to phpBB version 2.0.17 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for nested BBCode URL tags cross-site scripting vulnerability in phpBB <= 2.0.16";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-6])([^0-9]|$))") security_note(port);
}
