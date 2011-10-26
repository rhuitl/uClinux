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
 script_id(10141);
 script_bugtraq_id(110);
 script_version ("$Revision: 1.17 $");

 name["english"] = "MetaInfo servers";
 name["francais"] = "MetaInfo servers";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote MetaInfo server
allows remote users to read arbitrary
files by entering '../' in the URL. 
For instance :

	GET ../smusers.txt HTTP/1.0
will read 'smusers.txt'.

Solution : disable this server or upgrade.

Risk factor : High";

 desc["francais"] = "Le serveur MetaInfo distant
permet aux utilisateurs de lire
des fichiers arbitraires, pourvu
que leur noms soit précédés par
'../'
Exemple :
	GET ../smusers.txt HTTP/1.0
Lira le fichier smusers.txt

Solution : désactivez ce serveur ou mettez-le à jour.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Read everything using '../' in the URL";
 summary["francais"] = "Accède à n'importe quel fichier en utilisant '../'";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports(5000);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = 5000;
if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"../smusers.txt", port:port);
  send(socket:soc, data:buf);
  rep = recv_line(socket:soc, length:4096);
  if(" 200 " >< rep)security_hole(port);
  http_close_socket(soc);
 }
}
