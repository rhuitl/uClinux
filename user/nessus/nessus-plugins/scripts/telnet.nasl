#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10280);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0619");
 
 name["english"] = "Telnet";
 name["francais"] = "Telnet";
 name["deutsch"] = "Telnet";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "The Telnet service is running.
This service is dangerous in the sense that it is not ciphered - that is, 
everyone can sniff the data that passes between the telnet client
and the telnet server. This includes logins and passwords.


Solution:
If you are running a Unix-type system, OpenSSH can be used instead of telnet.
For Unix systems, you can comment out the 'telnet' line in /etc/inetd.conf.  
For Unix systems which use xinetd, you will need to modify the telnet services
file in the /etc/xinetd.d folder.  After making any changes to xinetd or 
inetd configuration files, you must restart the service in order for the 
changes to take affect.

In addition, many different router and switch manufacturers support SSH as a 
telnet replacement. You should contact your vendor for a solution which uses 
an encrypted session. 


Risk factor : Low";


 desc["francais"] = "Le service Telnet tourne.
Ce service est dangereux dans le sens où la communication
entre le serveur et le client n'est pas chiffrée, 
ce qui permet à n'importe qui de sniffer les données
qui passent entre le client et le serveur - ce qui
inclut les noms d'utilisateurs et leur mot de passe.

Vous devriez désactiver ce service et utiliser
OpenSSH à la place (www.openssh.com)

Solution : désactivez ce service dans /etc/inetd.conf.

Facteur de risque : Faible";

 desc["deutsch"] = "Der Telnet Dienst ist verfügbar. 
Dieser Dienst wird nicht verschlüsselt und ist daher als 
gefährlich einzustufen. Dies bedeutet das ein Angreifer die 
Daten, die zwischen dem Telnet-Client und Telnet-Server 
ausgetauscht werden, mitlesen kann. Dies beinhaltet sowohl
Benutzernamen wie auch Passwörter.

Dieser Dienst sollte deaktiviert werden, und anstelle dessen 
OpenSSH (www.openssh.com) verwendet werden.

Risikofaktor: Niedrig

Lösung: Deaktivieren des Dienstes in /etc/inetd.conf";


 script_description(english:desc["english"], francais:desc["francais"],
 deutsch:desc["deutsch"]);
 
 summary["english"] = "Checks for the presence of Telnet";
 summary["francais"] = "Vérifie la présence du service Telnet";
 summary["deutsch"] = "Überprüft auf Existenz des Telnet Dienstes"; 
 
 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
                deutsch:"Dieses Skript ist urheberrechtlich geschützt (C) 1999 Renaud Deraison");

 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 family["deutsch"] = "Nutzlose Dienste";

 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/telnet");
if(!port){
	p = known_service(port:23);
	if(p && p != "telnet") exit(0);
	port = 23;
	}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = telnet_negotiate(socket:soc);
  close(soc);
  if(r) {
#    security_note(port);
    set_telnet_banner(port: port, banner: r);
    register_service(port:port, proto:"telnet");
  }
 }
}
