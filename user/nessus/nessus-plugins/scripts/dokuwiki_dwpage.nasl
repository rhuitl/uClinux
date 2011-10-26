#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that should be removed or
protected. 

Description :

The remote host is running DokuWiki, an open-source wiki application
written in PHP. 

The installed version of DokuWiki includes a script, 'bin/dwpage.php',
that is intended as a commandline tool for modifying pages.  By
accessing it through the web, an unauthenticated remote attacker can
abuse it to view local files and even execute arbitrary code, both
subject to the privileges of the web server user id. 

See also :

http://retrogod.altervista.org/dokuwiki_2006-03-09b_cmd.html
http://milw0rm.com/exploits/2322
http://www.freelists.org/archives/dokuwiki/09-2006/msg00064.html

Solution :

Limit access to DokuWiki's 'bin' directory using, say, a .htaccess
file or remove the affected script. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22315);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(19911);

  script_name(english:"DokuWiki dwpage.php Accessibility Vulnerability");
  script_summary(english:"Checks whether DocuWiki dwpage.php is accessible via http");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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
if (thorough_tests) dirs = make_list("/doku", "/dokuwiki", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Call the script's help function
  req = http_get(item:string(dir, "/bin/dwpage.php?-h"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("Usage: dwpage.php [opts] <action>" >< res)
  {
    security_hole(port);
    exit(0);
  }
}
