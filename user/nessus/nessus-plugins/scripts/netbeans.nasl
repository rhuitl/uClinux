#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10149);
 script_bugtraq_id(816);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-1527");
 name["english"] = "NetBeans Java IDE";
 name["francais"] = "NetBeans Java IDE";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running NetBeans (recently renamed to
Forte') Java IDE. There is a bug in this version that allows
anyone to browse the files on this system.


Solution : Set the HTTP server 'Enable' to FALSE in Project settings
Risk factor : High";

 desc["francais"] = "
Le système distant fait tourner l'IDE Java NetBeans (renommé récemment Forte')
Il y a un problème dans cette version qui permet à n'importe qui
de browser les fichiers présents sur ce système.

Solution : Mettez le 'Enable' de HTTP Server à FAUX dans les project settings
";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "determines whether the remote root directory is browseable";
 summary["francais"] = "determines whether the remote root directory is browseable";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80, 8082);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

function netbeans(port)
{
if(get_port_state(port))
{
  data = http_get_cache(item:"/", port:port);
  data_low = tolower(data);
  seek = "<title>index of /</title>";
  if(seek >< data_low)
  {
   if("netbeans" >< data_low) { 
	security_hole(port);
	exit(0);
	}
   }
 }
}

#
# NetBeans might be running on another port.
# 
if ( thorough_tests ) netbeans(port:8082);

port = get_http_port(default:80);
if(!port)exit(0);
if( port != 8082 || thorough_tests == 0 ) netbeans(port:port);
