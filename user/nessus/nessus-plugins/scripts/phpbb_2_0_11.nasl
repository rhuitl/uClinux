#
# (C) Tenable Network Security
#


if (description) {
  script_id(17205);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0258", "CVE-2005-0259"); 
  script_bugtraq_id(12618, 12621, 12623);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14038");
    script_xref(name:"OSVDB", value:"14039");
    script_xref(name:"OSVDB", value:"14040");
    script_xref(name:"OSVDB", value:"14041");
    script_xref(name:"OSVDB", value:"14042");
    script_xref(name:"OSVDB", value:"14043");
  }
 
  name["english"] = "Multiple vulnerabilities in phpBB 2.0.11 and older";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running phpBB version 2.0.11 or older.  Such
versions suffer from multiple vulnerabilities:

  - full path display on critical messages.
  - full path disclosure in username handling caused by a PHP 4.3.10 bug.
  - arbitrary file disclosure vulnerability in avatar handling functions.
  - arbitrary file unlink vulnerability in avatar handling functions.
  - path disclosure bug in search.php caused by a PHP 4.3.10 bug.
  - path disclosure bug in viewtopic.php caused by a PHP 4.3.10 bug.

The path disclosure vulnerabilities can be exploited by remote
attackers to reveal sensitive information about the installation that
can be used in further attacks against the target. 

To exploit the avatar handling vulnerabilities, 'Enable gallery
avatars' must be enabled on the target (by default, it is disabled)
and an attacker have a phpBB account on the target. 

See also :

http://www.phpbb.com/support/documents.php?mode=changelog#2011

Solution : 

Upgrade to phpBB 2.0.12 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Multiple vulnerabilities in phpBB version 2.0.11 and older";
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

  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[01])([^0-9]|$))")
    security_note(port);
}
