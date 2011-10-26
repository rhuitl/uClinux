#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11587);
 script_bugtraq_id(7406);
 script_version ("$Revision: 1.7 $");

 script_name(english:"XMB SQL Injection");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote host is running XMB Forum, a web forum written in PHP. 

According to its banner, this forum is vulnerable to a SQL injection
bug which may allow an attacker to steal the passwords hashes of any
user of this forum, including the forum administrator.  Once he has
the password hashes, he can easily setup a brute-force attack to crack
the users passwords and then impersonate them.  If the administrator
password is obtained, an attacker may even edit the content of this
website. 

See also : 

http://www.securityfocus.com/archive/1/319411

Solution: 

Upgrade to XMB Forum 1.8 SP1 or newer.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if XMB forums is vulnerable to a sql injection attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


if (thorough_tests) dirs = make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Look for the version number in the login script.
  req = http_get(item:string(dir, "/misc.php?action=login"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    # Sample banners:
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.05</font><br />
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.5 RC4: Summer Forest<br />
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 Magic Lantern Final<br></b>
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 v2b Magic Lantern Final<br></b>
    #   Powered by XMB 1.8 Partagium SP1<br />
    #   Powered by XMB 1.9 Nexus (beta)<br />
    #   Powered by XMB 1.9.1 RC1 Nexus<br />
    #   Powered by XMB 1.9.2 Nexus (pre-Alpha)<br />
    egrep(string:res, pattern:"Powered by .*XMB(<[^>]+>)* v?(0\..*|1\.([0-7]+\..*|8 Partagium<br))")
  ) {
    security_warning(port);
    exit(0);
 }
}
