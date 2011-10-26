#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10085);
 script_bugtraq_id(271);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0079");
 script_name(english:"Ftp PASV denial of service",
 	     francais:"Déni de service via la commande ftp PASV");
 
 script_description(english:"The remote FTP server allows users to make any amount
of PASV commands, thus blocking the free ports for legitimate services and
consuming file descriptors.

Solution: upgrade your FTP server to a version which solves this problem.

Risk factor : Medium",

	francais:"Certains serveurs FTP laissent les utilisateurs entrer
un nombre non-fini de commandes PASV, ce qui bloque les ports libres pour 
les services légitimes.

Solution : changez votre serveur FTP pour une version qui résoud ce probleme.

Facteur de risque : Moyen");

 script_summary(english:"Determines if a PASV DoS is feasible",
 francais:"Determine si un déni de service via la commande PASV est faisable");
 
 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais: "Ce script est Copyright (C) 1999 Renaud Deraison");
 
 script_family(english:"FTP");
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#

include('ftp_func.inc');
include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(!login)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
if(ftp_authenticate(socket:soc, user:login, pass:password))
{
 port1 = ftp_pasv(socket:soc);
 for(i=0;i<40;i=i+1)port2 = ftp_pasv(socket:soc);
 if(port1 == port2){
	close(soc);
	exit(0);
	}
 if(port2){
	soc1 = open_sock_tcp(port1, transport:get_port_transport(port));
 	if(soc1>0){
		security_warning(port);
		close(soc1);
		}
	}
} 
close(soc);
}
