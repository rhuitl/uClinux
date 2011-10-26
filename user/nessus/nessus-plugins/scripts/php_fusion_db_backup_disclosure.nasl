#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14356);
 script_cve_id("CVE-2004-1724");
 script_bugtraq_id(10974);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "PHP-Fusion Database Backup Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone
to information disclosure.

Description :

A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to obtain a dump of the remote database.  PHP-Fusion
has the ability to create database backups and store them on the web
server, in the directory '/fusion_admin/db_backups/'.  Since there is
no access control on that directory, an attacker may guess the name of
a backuped database and download it. 

See also : 

http://echo.or.id/adv/adv04-y3dips-2004.txt

Solution : 

Use a .htaccess file or the equivalent to control access to files in
the backup directory. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("php_fusion_detect.nasl", "no404.nasl");
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
if (get_kb_item("www/no404/"+port)) exit(0);

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items = eregmatch(string:kb, pattern:"(.*) under (.*)");
ver   = items[1];
loc   = items[2];

if ( ver =~ "^([0-3][.,]|4[.,]00)" )
{
  req = http_get(item:string(loc, "/fusion_admin/db_backups/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( r == NULL ) exit(0);
  if ( egrep(pattern:"^HTTP/.* 200 .*", string:r) )
	{ 
  	security_warning(port);
	}
  exit(0);
}
