#
# (C) Tenable Network Security
#


if (description) {
  script_id(20373);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4602");
  script_bugtraq_id(16082, 16097);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22159");
  }

  script_name(english:"MyBB < 1.01 SQL Injection Vulnerabilities");
  script_summary(english:"Checks for SQL injection vulnerabilities in MyBB < 1.01");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple SQL injection vulnerabilities. 

Description :

The installed version of MyBB fails to validate user input to the
'mybbadmin' cookie in the 'admin/global.php' script as well as the
extension of a file upload before using them in database queries.  An
attacker may be able to leverage these issues to disclose sensitive
information, modify data, or launch attacks against the underlying
database. 

Note that exploitation of the second issue may require authentication
while the first does not. 

See also :

http://www.securityfocus.com/archive/1/420573
http://community.mybboard.net/showthread.php?tid=5633

Solution : 

Upgrade to MyBB version 1.01 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit flaw in the cookie to generate a syntax error.
  req = http_get(
    item:string(
      dir, "/admin/global.php?",
      "action=", SCRIPT_NAME
    ), 
    port:port
  );
  magic = rand_str(length:8);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: mybbadmin='", magic, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a syntax error involving the word "nessus".
  #
  # nb: the code splits the cookie on "_" so we can't just use our script 
  #     name as we usually do.
  if (egrep(pattern:"an error in your SQL syntax.+ WHERE uid=''" + magic, string:res)) {
    security_warning(port);
    exit(0);
  }
}
