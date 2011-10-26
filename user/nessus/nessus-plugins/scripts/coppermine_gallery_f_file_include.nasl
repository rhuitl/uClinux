#
# (C) Tenable Network Security
#


if (description) {
  script_id(20984);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0873");
  script_bugtraq_id(16718);

  script_name(english:"Coppermine Photo Gallery f Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for f parameter remote file include vulnerability in Coppermine Photo Gallery");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include vulnerability. 

Description :

The installed version of Coppermine Photo Gallery fails to sanitize
user input to the 'f' parameter in the 'docs/showdoc.php' script
before using it in a PHP 'include()' function.  An unauthenticated
attacker may be able to exploit this flaw to view arbitrary files or
to execute arbitrary PHP code, possibly taken from third-party hosts. 

Note that successful exploitation either requires that the remote host
be running Windows or that it have some type of Samba share. 

See also :

http://retrogod.altervista.org/cpg_143_adv.html
http://www.securityfocus.com/archive/1/425387/30/0/threaded
http://coppermine-gallery.net/forum/index.php?topic=28062.0

Solution :

Patch the affected script as recommended in the vendor advisory
referenced above. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
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

  # Try to exploit the flaw to read a file in the directory.
  #
  # nb: the vendor patch always displays 'index.htm' so the caller
  #     can't request another file.
  file = 'COPYING';
  req = http_get(
    item:string(
      dir, "/docs/showdoc.php?",
      "f=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the GPL.
  if ("GNU GENERAL PUBLIC LICENSE" >< res) {
    security_note(port);
    exit(0);
  }
}

