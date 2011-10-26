#
# (C) Tenable Network Security
#


if (description) {
  script_id(17970);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1011");
  script_bugtraq_id(12985);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15238");

  name["english"] = "SiteEnable XSS and SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple flaws. 

Description :

The remote host is running a version of the SiteEnable CMS package
that is prone to several vulnerabilities :

  - SQL Injection Vulnerability
    Due to a failure to properly sanitize user input to the 'sortby' 
    parameter of the 'content.asp' script, an attacker can 
    execute SQL queries against the underlying database.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code through
    the 'contenttype' parameter (and likely others) of the 
    'content.asp' script to be executed in a user's browser in
    the context of the affected website.

See also :

http://securitytracker.com/alerts/2005/Apr/1013631.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for XSS and SQL injection vulnerabilities in SiteEnable";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Check various directories for SiteEnable.
foreach dir (cgi_dirs()) {
  # Pull up goto.asp and look for a string identifying SiteEnable.
  req = http_get(item:string(dir, "/goto.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's SiteEnable.
  if ('A "gotourl=" parameter must be passed to this page' >< res) {
    # Try the exploit.
    req = http_get(
      item:string(
        dir, "/content.asp?",
        "CatId=&",
        "ContentType=&",
        "keywoards=Contact&",
        "search=%3E&",
        "do_search=1&",
        # nb: cause a syntax error.
        "sortby=foo%20bar"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we get a database error, there's a problem.
    if (egrep(string:res, pattern:"Microsoft JET Database Engine.+error '80040e10'", icase:TRUE)) {
      security_warning(port);
      exit(0);
    }
  }
}
