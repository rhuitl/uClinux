#
# (C) Tenable Network Security
#


if (description) {
  script_id(20375);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-4606");
  script_bugtraq_id(16085);
  script_xref(name:"OSVDB", value:"22148");

  script_name(english:"Web Wiz txtUserName Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for txtUserName Parameter SQL injection vulnerability in Web Wiz products");
 
  desc = "
Synopsis :

The remote web server has an ASP application that is affected by a SQL
injection vulnerability. 

Description :

The remote host is running an ASP application from Web Wiz, such as
Password Login, Journal, Polls, or Site News. 

The installed version of the Web Wiz application fails to validate
user input to the 'txtUserName' parameter of the
'admin/check_user.asp' script before using it in database queries.  An
unauthenticated attacker may be able to leverage this issue to bypass
authentication, disclose sensitive information, modify data, or launch
attacks against the underlying database. 

See also :

http://www.kapda.ir/advisory-167.html

Solution : 

Upgrade to Web Wiz Password Login 1.72 / Journal 1.0.1 / Polls 3.07 /
Site News 3.07 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

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
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/journal", "/news", "/poll", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the script exists.
  req = http_get(item:string(dir, "/admin/check_user.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(pattern:"^Location: +unauthorised_user_page.htm", string:res)) {
    # Try to exploit the flaw to generate a syntax error.
    postdata = string(
      "txtUserName='", SCRIPT_NAME, "&",
      "txtUserPass=nessus&",
      "Submit=enter"
    );
    req = string(
      "POST ", dir, "/admin/check_user.asp HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we get a syntax error.
    if (
      string("query expression 'tblConfiguration.Username ='", SCRIPT_NAME) >< res &&
      egrep(pattern:"Microsoft OLE DB Provider for ODBC Drivers.+error '80040e14'", string:res)
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
