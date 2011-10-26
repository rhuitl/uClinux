#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21729);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18484);

  script_name(english:"Wikka Local File Include Vulnerability");
  script_summary(english:"Tries to read a local file in Wikka");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The remote host is running Wikka, a lightweight, open-source wiki
application written in PHP. 

The version of Wikka installed on the remote host has a programming
error in the 'Method()-method' in 'wikka.php'.  By leveraging this
issue, an unauthenticated attacker may be able to access arbitrary PHP
files on the affected host and execute them, subject to the privileges
of the web server user id. 

Note that successful exploitation is unaffected by the setting of PHP
'register_globals' but only works with files with the extension
'.php'. 

See also :

http://wush.net/trac/wikka/ticket/36
http://wikkawiki.org/WikkaReleaseNotes#hn_Wikka_1.1.6.2

Solution :

Upgrade to Wikka version 1.1.6.2 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
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
if (thorough_tests) dirs = make_list("/wikka", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(
    item:string(
      dir, "/wikka.php?",
      "wakka=HomePage/../../actions/wikkachanges"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see the release notes.
  if ("<h2>Wikka Release Notes</h2>" >< res) {
    security_warning(port);
    exit(0);
  }
}
