#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10470);
 script_bugtraq_id(1497);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0642");
 
 name["english"] = "WebActive world readable log file";
 name["francais"] = "Fichier de log WebActive lisible par tous";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to obtain the remote WebActive logfile by 
requesting the file /active.log

An attacker may use this to obtain valuable information about
your site, such as who visits it and how popular it is.

Solution : use another web server, as WebActive is not maintained.
If you are using WindowsNT, then remove read access to this
file.

Risk factor : Low";

 desc["francais"] = "
Il est possible d'obtenir le fichier de log webactive en
demandant le fichier /active.log

Un pirate peut utiliser ce problème pour obtenir
plus d'informations sur ce serveur, telles que sa popularité
et le profil de ses visiteurs.

Solution : utilisez un autre serveur web, puisque WebActive
n'est plus mis à jour. Si vous etes sous WindowsNT, alors
mettez des restrictions de lecture sur ce fichier.

Facteur de risque : Faible";


 script_description(english:desc["english"]);
 
 summary["english"] = "Requests /active.log";
 summary["francais"] = "Demande /active.log";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
req = http_get(item:"/active.log", port:port);
r = http_keepalive_send_recv(port:port, data:req);
if("WEBactive Http Server" >< r)
  {
    security_warning(port);
  }
