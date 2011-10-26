#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(18430);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1888");
  script_bugtraq_id(13861);

  name["english"] = "MediaWiki Page Template Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-site
scripting attacks. 

Description :

According to its version number, the version of Mediawiki installed on
the remote host is vulnerable to cross-site scripting attacks because of
its failure to sanitize input passed to certain HTML attributes by
including a template inside a style directive when editing an entry.  An
attacker can leverage this flaw to inject arbitrary HTML and script code
to be executed by a user's browser within the context of an affected
site. 

See also : 

http://bugzilla.wikimedia.org/show_bug.cgi?id=2304

Solution : 

Upgrade to MediaWiki 1.3.13 or later if using 1.3 legacy series;
otherwise, switch to 1.4.5 or later. 

Risk factor :

Low / CVSS Base Score : 1 
(AV:R/AC:L/Au:R/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for page template cross-site scripting vulnerability in MediaWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])|4\.[0-4]($|[^0-9.])|5 alpha1)") {
    security_note(port);
    exit(0);
  }
}
