#
# (C) Tenable Network Security
#


if (description) {
  script_id(18055);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1134");
  script_bugtraq_id(13161);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15542");

  name["english"] = "Serendipity exit.php SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The version of Serendipity installed on the remote host allows an
attacker to pass arbitrary SQL code through the 'url_id' and
'entry_id' parameters of the 'exit.php' script.  These flaws may lead
to disclosure / modification of data or attacks against the underlying
database application. 

See also :

http://www.s9y.org/63.html#A9

Solution : 

Upgrade to Serendipity 0.7.1 or to 0.8 or greater.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerabilities in Serendipity exit.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # If safe checks are enabled...
  if (safe_checks()) {
    # nb: versions 0.7 and lower as well as 0.8-beta6 and
    #     lower may be vulnerable.
    if (ver =~ "0\.([1-6]|7([^0-9]|$)|8-beta[1-6])") security_warning(port);
  }
  # Otherwise...
  else {
    # Try to exploit the vulnerability.
    req = http_get(
      item:string(
        dir, "/exit.php?",
        "entry_id=1&",
        # This should issue a redirect to 'nessus'.
        "url_id=1%20UNION%20SELECT%20'nessus'--"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # There's a problem if there's a redirect to 'nessus'.
    if (
      egrep(string:res, pattern:"^HTTP/1\.1 301") &&
      egrep(string:res, pattern:"^Location: nessus")
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
