#
# (C) Tenable Network Security
#


if (description) {
  script_id(18420);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1810");
  script_bugtraq_id(13809);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16905");
  }

  name["english"] = "WordPress cat_ID SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description : 

The version of WordPress installed on the remote host fails to
properly sanitize user-supplied input to the 'cat_ID' variable in the
'template-functions-category.php' script.  This failure may allow an
attacker to influence database queries resulting in the disclosure of
sensitive information and possibly attacks against the underlying
database itself. 

***** Nessus has determined the vulnerability exists on the remote
***** host simply by checking the version number of WordPress 
***** installed there.

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=111817436619067&w=2 
http://wordpress.org/development/2005/05/security-update/

Solution : 

Upgrade to WordPress version 1.5.1.2 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cat_ID SQL injection vulnerability in WordPress";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("wordpress_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0\.|1\.([0-4]|5([^0-9.]+|$|\.0|\.1([^0-9.]|$)|\.1\.[01][^0-9])))") {
    security_warning(port);
    exit(0);
  }
}
