#
# (C) Tenable Network Security
#


if (description) {
  script_id(19949);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-3167");
  script_bugtraq_id(15024, 15041);

  name["english"] = "MediaWiki < 1.3.17 / 1.4.11 / 1.5.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities.

Description :

According to its version number, the version of Mediawiki installed on
the remote host is vulnerable to data corruption bug involving the
submission handling routine when faced with malformed URLs.  Under
certain circumstances, this may corrupt the previous revision in the
database.  A spam bot known to be active in the wild reportedly can
trigger this issue. 

In addition, the application suffers from a cross-site scripting
vulnerability due to its failure to sanitize user-input for HTML inline
style attributes. 

See also : 

http://sourceforge.net/forum/forum.php?forum_id=501174

Solution : 

Upgrade to MediaWiki 1.3.17 or later if using 1.3.x legacy series; to
1.4.11 or later if using 1.4.x; otherwise to 1.5.0 or later. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:I)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in MediaWiki < 1.3.17 / 1.4.11 / 1.5.0";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('global_settings.inc');
include("http_func.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-6])|4\.([0-9]($|[^0-9])|10)|5 (alpha|beta))") {
    security_warning(port);
    exit(0);
  }
}
