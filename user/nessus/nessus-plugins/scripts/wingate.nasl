#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10309);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0291");
 
 name["english"] = "Passwordless Wingate installed";
 name["francais"] = "Wingate est installé sans mot de passe";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "Wingate is a program that allows
a Windows98 computer to act as a proxy.
Unfortunately, the default configuration is too 
permissive and allows anyone to use this computer 
to connect anywhere, thus hiding his real IP address.

This WinGate server does not ask for any
password, and thus can be used by an attacker
from anywhere as a telnet relay.

Solution : check the WinGate configuration.

Risk factor : High";

 desc["francais"] = "Wingate est un programme qui
permet de transformer un poste Windows98 en
proxy. 
Hélas, ce programme vient avec une configuration
trop permissive qui permet à n'importe qui de se
servir de cette machine pour se connecter n'importe
où, cachant ainsi la vrai adresse IP de la personne
en question.

Ce serveur Wingate ne demande aucun mot de passe,
et par conséquent peut etre utilisé par des pirates
comme relais telnet.

Solution : vérifiez la configuration de WinGate.

Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if wingate is installed"; 
 summary["francais"] = "Détermine si wingate est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Firewalls"; 
 family["francais"] = "Firewalls";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/telnet");
if(!port) port = 23;

if(get_port_state(port))soc = open_sock_tcp(port);
else exit(0);
if(soc)
{
buffer = recv(socket:soc, length:1);
n = strlen(buffer);
if(n == 0)exit(0);

buffer = recv(socket:soc, length:7);
if(!buffer){
		close(soc);
		exit(0);
 	  }	    
b = string("localhost\r\n");
send(socket:soc, data:b);
r = recv(socket:soc, length:1024);
if(!r){
	close(soc);
	exit(0);
	}
r = tolower(r);
for(i=0;i<11;i=i+1){
		d = recv(socket:soc, length:1);
		if(!d){
			close(soc);
			exit(0);
			}
		}
r = recv(socket:soc, length:100);
r = tolower(r);
if(("connecting to host" >< r)){
	security_hole(port);
	set_kb_item(name:"wingate/enabled", value:TRUE);
	}
close(soc);
}
