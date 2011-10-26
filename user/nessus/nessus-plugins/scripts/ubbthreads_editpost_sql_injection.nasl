#
# (C) Tenable Network Security
#


if (description) {
  script_id(17316);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0726");
  script_bugtraq_id(12784);

  name["english"] = "UBB.threads editpost.php SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to 
SQL injection attacks.

Description :

According to its banner, the remote host is running a version of
UBB.threads that fails to sufficiently sanitize the 'Number' parameter
before using it in SQL queries in the 'editpost.php' script.  As a
result, a remote attacker can pass malicious input to database queries,
potentially resulting in data exposure, modification of the query logic,
or even data modification or attacks against the database itself. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=111056135818279&w=2

Solution : 

Upgrade to UBB.threads version 6.5.1.1 or greater.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in UBB.threads editpost.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("ubbthreads_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: actually exploiting this generally requires you be be editing your
  #     own post, and most boards require posters to authenticate first.
  #
  # nb: the changelog claims the vulnerability was fixed in 6.5.1.1 so
  #     we should assume everthing below that is vulnerable.
  if (ver =~ "^([0-5]\.|6\.([0-4][^0-9]|5$|5\.0|5\.1([^0-9.]|$)))") 
    security_warning(port);
}
