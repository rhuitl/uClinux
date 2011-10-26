#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16122);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(12207);
 
 name["english"] = "PHPWind Board Remote File Include Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows for arbitrary
code execution. 

Description :

The remote host is running PHPWind Board, a web based bulletin board. 

There is a flaw in older versions of this software in the file
'faq.php' which may allow an attacker to gain a shell on this host. 

See also : 

http://www.54hack.info/txt/phpwind.doc

Solution: 

Upgrade to PHPwind 2.0.2 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of PHPWind Board.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "faq.php?skin=../../admin/manager&tplpath=admin"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if("input type=text name=password size=40 value=" >< r) 
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

