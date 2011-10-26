#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Date: Mon, 03 Mar 2003 13:57:43 +0100
# Message-ID: <F33JEyTeTaj1qNIFR2e000195ec@hotmail.com>
# Subject: [VulnWatch] WebChat (PHP)

if(description)
{
 script_id(11315);
 script_bugtraq_id(7000);
 script_version ("$Revision: 1.9 $");

 name["english"] = "Webchat code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
remote code inclusion flaw. 

Description :

The version of Webchat installed on the remote host allows an attacker
to read local files or execute PHP code, possibly taken from third-
party sites, subject to the permissions of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/313606

Solution : 

Contact the vendor for a patch or remove the application.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Webchat's defines.php";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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
 req = http_get(item:string(loc, "/defines.php?WEBCHATPATH=http://xxxxxxxx/"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if("http://xxxxxxxx/db_mysql.php" >< r )
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir (dirs)
{
 check(loc:dir);
}
