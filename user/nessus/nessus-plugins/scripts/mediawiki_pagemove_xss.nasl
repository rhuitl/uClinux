#
# (C) Tenable Network Security
# 


if (description) {
  script_id(18644);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2215");
  script_bugtraq_id(14181);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17763");
  }

  name["english"] = "MediaWiki Page Move Template Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-site
scripting attacks. 

Description :

According to its version number, the version of Mediawiki installed on
the remote host is vulnerable to cross-site scripting attacks because of
its failure to sanitize input passed to the page move template.  This
flaw could be used to inject arbitrary HTML and script code into a
user's browser resulting in the theft of cookies, misrepresentation of
the site, and other such attacks. 

See also :

http://bugzilla.wikimedia.org/show_bug.cgi?id=2304

Solution : 

If using MediaWiki 1.4.x, upgrade to 1.4.6 or later; if using MediaWiki
1.5.x, upgrade to 1.5.0 beta3 or later. 

Risk factor :

Low / CVSS Base Score : 1 
(AV:R/AC:L/Au:R/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for page move template cross-site scripting vulnerability in MediaWiki";
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

  if (ver =~ "^1\.(4\.[0-5]($|[^0-9.])|5.* (alpha|beta[12]))") {
    security_note(port);
    exit(0);
  }
}
