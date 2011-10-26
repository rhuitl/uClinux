#
# This script was written by Gregory Duchemin <plugin@intranode.com>
#
# See the Nessus Scripts License for details
#
#
# Title: Interscan VirusWall Remote configuration Vulnerability.
#
#
#

#### REGISTER SECTION ####

if(description)
{
 script_id(10733);
 script_bugtraq_id(2579);
 script_cve_id("CVE-2001-0432");
 script_version ("$Revision: 1.14 $");

#Name used in the client window.

name["english"] = "InterScan VirusWall Remote Configuration Vulnerability";
name["francais"] = "Possibilité de modifier à distance sans autorisation la configuration de Interscan VirusWall.";
script_name(english:name["english"], francais:name["francais"]);


#Description appearing in the Nessus client window when clicking on the name.

desc["english"]="The management interface used with the Interscan VirusWall 
uses several cgi programs that may allow a malicious user to remotely 
change the configuration of the server without any authorization using 
maliciously constructed querystrings.

Solution : don't connect the management interface directly to the Internet
Risk factor : High";

desc["francais"]="L'interface d'administration du produit Interscan 
VirusWall utilise de nombreux cgi qui peuvent permettre à un utilisateur
malicieux de modifier à distance la configuration du serveur sans aucune 
autorisation et en utilisant des requêtes GET malicieusement construites.

Facteur de risque : élevé";

script_description(english:desc["english"], francais:desc["francais"]);




#Summary appearing in the tooltips, only one line. 

summary["english"]="Check if the remote Interscan is vulnerable to remote reconfiguration.";
summary["francais"]="Vérifie si Interscan est vulnérable à une reconfiguration à distance.";	
script_summary(english:summary["english"], francais:summary["francais"]);


#Test it among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);

#Copyright stuff

script_copyright(english:"INTRANODE - 2001");


 
#Category in wich script must be stored.

family["english"]="CGI abuses";
family["francais"]="Abus de CGI";
script_family(english:family["english"], francais:family["francais"]);


script_dependencie("http_version.nasl");


#optimization, stop here if either no web service was found by find_service.nes plugin or no port 80 was open.

script_require_ports(80, "Services/www");
 
exit(0);
}




#### ATTACK CODE SECTION ####



include("http_func.inc");
include("http_keepalive.inc");
#search web port in knowledge database

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


request = http_get(item:"/interscan/cgi-bin/FtpSave.dll?I'm%20Here", port:port);
receive = http_keepalive_send_recv(port:port, data:request);

signature = "These settings have been saved";

if (signature >< receive)
{
 security_hole(port);
}

