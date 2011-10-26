#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Tue, 25 Mar 2003 12:11:24 +0300
#  From: "Over_G" <overg@mail.ru>
#  To: vuln@security.nnov.ru, bugtraq@securityfocus.com
#  Subject: CSS in PHP WEB CHAT
#
#
# NOTE: It was impossible to check for this flaw, as the author
# apparently do not distribute this product any more (which makes me
# wonder about the impact of this 'flaw')




if(description)
{
 script_id(11470);
 script_bugtraq_id(7190);
 script_version ("$Revision: 1.10 $");


 name["english"] = "WebChat XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a cross site scripting attack through
its web chat module :

- An attacker may create a new user with a bogus email address containing
  javascript code
- Then the profile of the newly created user or the 'lost password' page
  for this user will display the unprocessed java script to the user
  
  
An attacker may use this flaw to steal the cookies of your regular users

Risk factor : Medium
Solution : None at this time, contact the vendor at http://www.webscriptworld.com ";


 script_description(english:desc["english"]);
 
 summary["english"] = "XSS in WebChat";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

if ( ! safe_checks() ) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


gdir = make_list(cgi_dirs());

dirs = make_list("", "/chat", "/chat_dir");
foreach d (gdir)
{
  dirs = make_list(dirs, string(d, "/chat"), string(d, "/chat_dir"), d);
}


foreach dir (dirs)
{
 rnd = rand();
 url1 = string(dir, "/register.php?register=yes&username=nessus", rnd, "&email=<script>x=10;</script>&email1=<script>x=10;</script>");
 
 req = http_get(item:url1, port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(egrep(pattern:"HTTP/.* 200 .*", string:res))
 {
  url2 = string(dir,"/login.php?option=lostpasswd&username=nessus", rnd);
  req = http_get(item:url2, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( res == NULL ) exit(0);
  if("<script>x=10;</script>" >< res){ security_warning(port); exit(0); }
 }
}
