#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# This script is released under the GNU GPL v2
#

if(description)
{
  script_id(19764);
  script_cve_id("CVE-2005-3015");
  script_bugtraq_id(14845, 14846);
  script_version("$Revision: 1.5 $");
  
  script_name(english:"Lotus Domino Src and BaseTarget XSS");

 desc["english"] = "
Synopsis :

The remote web server is vulnerable to cross-site scripting issues.

Description :

The remote host runs Lotus Domino web server.

This version is vulnerable to multiple cross-site scripting due to a
lack of sanitization of user-supplied data.  Successful exploitation of
this issue may allow an attacker to execute malicious script code in a
user's browser within the context of the affected application. 

Solution : 

Upgrade to Domino 6.5.2 or newer

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

  script_description(english:desc["english"]);
  script_summary(english:"Checks Lotus Domino XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if ( "Lotus" >!< banner ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

buf = http_get(item:"/", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

matches = egrep(pattern:'src=.+(.+?OpenForm.+BaseTarget=)', string:r);
foreach match (split(matches)) 
{
       match = chomp(match);
       matchspec=eregmatch(pattern:'src="(.+?OpenForm.+BaseTarget=)', string:match);
       if (!isnull(matchspec))
       {
	       buf = http_get(item:string(matchspec[1],'";+<script>alert(foo)</script>;+var+mit="a'), port:port);
	       r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	       if( r == NULL )exit(0);

	       if ("<script>alert(foo)</script>" >< r)
	       {
		       security_note(port);
	       }
       }
}
exit(0);
