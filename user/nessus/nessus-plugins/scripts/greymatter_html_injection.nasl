#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16120);
 script_bugtraq_id(12189,12182,12184);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Noah Grey Greymatter GM-Comments.CGI HTML Injection Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Greymatter, a web based log and journal 
maintenance system implemented in Perl. 


The remote version of this software is vulnerable to an HTML injection
vulnerability due to a lack of filtering on user-supplied input in the
file 'gm-comments.cgi'. An attacker may exploit this flaw to perform a 
cross-site scripting attack against the remote host.

This software may be vulnerable to another HTLM injection vulnerability
in the file 'gm-cplog.cgi' and to a password disclosure vulnerability
in the file 'gm-token.cgi'.

Solution : None at this time.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Greymatter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
req = http_get(item:string(url, "/cgi-bin/gm-comments.cgi"), port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if ( egrep(pattern:">v[0-1](\.[0-2]([0-9])?(\.[0-9])?)?|(\.3(\.0)?)?(a|b|c|d)?\s*&#183;\s*&copy;(19[0-9][0-9]|200[0-5])-(19[0-9][0-9]|200[0-5])(.*?)Greymatter|Noah\sGrey(.*?)<", string:r))
 {
 security_warning(port);
 exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
