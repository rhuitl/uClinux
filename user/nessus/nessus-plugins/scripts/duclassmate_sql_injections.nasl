#
# (C) Tenable Network Security
#


if (description) {
  script_id(18566);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2049");
  script_bugtraq_id(14036);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17588");
    script_xref(name:"OSVDB", value:"17589");
  }

  name["english"] = "DUclassmate Multiple SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is vulnerable
to multiple SQL injection attacks. 

Description :

The remote host is running DUclassmate, a web-based classmates listing
and friends search application from DUware and written in ASP. 

The installed version of DUclassmate fails to properly sanitize user-
supplied input in several instances before using it in SQL queries. 
By exploiting these flaws, an attacker can affect database queries,
possibly disclosing sensitive data and launching attacks against the
underlying database. 

See also : 

http://echo.or.id/adv/adv19-theday-2005.txt
http://archives.neohapsis.com/archives/bugtraq/2005-06/0172.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple SQL injection vulnerabilities in DUclassmate";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws.
  req = http_get(
    item:string(
      dir, "/default.asp?",
      "iState=", SCRIPT_NAME, "'&",
      "nState=Utah"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like DUclassmate and...
    'href="assets/DUclassmate.css" rel="stylesheet"' >< res && 
    # there's a syntax error.
    string("Syntax error (missing operator) in query expression 'CIT_STATE = ", SCRIPT_NAME, "'") >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
