#
# (C) Tenable Network Security
#


if (description) {
  script_id(20385);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0146");
  script_bugtraq_id(16187);
  script_xref(name:"OSVDB", value:"22290");

  script_name(english:"ADODB sql Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for sql parameter SQL injection vulnerability in ADODB");
 
  desc = "
Synopsis :

The remote web server has a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote host is running ADODB, a database abstraction library for
PHP. 

The installed version of ADODB includes a test script named
'server.php' that fails to sanitize user input to the 'sql' parameter
before using it in database queries.  An attacker can exploit this
issue to launch SQL injection attacks against the underlying database. 

See also :

http://secunia.com/secunia_research/2005-64/advisory/

Solution : 

Remove the test script or set a root password for MySQL. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if ( !thorough_tests ) exit(0);


subdirs = make_list(
  "/adodb",                            # PHPSupportTickets
  "/core/adodb",                       # Mantis
  "/includes/third_party/adodb",       # Cerberus
  "/lib/adodb",                        # Cacti / Moodle / TikiWiki
  "/library/adodb",                    # dcp_portal
  "/libraries/adodb",                  # phpPgAdmin
  "/xaradodb"                          # Xaraya
);


# Loop through directories.
foreach dir (cgi_dirs()) {
  foreach subdir (subdirs) {
    # Try to exploit the flaw to generate a syntax error.
    req = http_get(
      item:string(
        dir, subdir, "/server.php?",
        "sql='", SCRIPT_NAME
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:"an error in your SQL syntax.+ near ''" + SCRIPT_NAME, string:res)) {
      security_warning(port);

      exit(0);
    }
  }
}
