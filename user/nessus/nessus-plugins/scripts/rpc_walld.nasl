#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10240);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0181");
 
 name["english"] = "walld service";
 name["francais"] = "Service walld";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The walld RPC service is running.  It is usually used by the administrator
to tell something to the users of a network by making a message appear
on their screen.

Since this service lacks any kind of authentication, an attacker
may use it to trick users into doing something (change their password,
leave the console, or worse), by sending a message which would appear to be
written by the administrator.

It can also be used as a denial of service attack, by continually sending 
garbage to the users screens, preventing them from working properly.

Solution : Disable this service.
Risk factor : Medium";


 desc["francais"] = "
Le service RPC walld tourne.
Il est usuellement utilisé par l'administrateur
d'un réseau pour communiquer un message aux
utilisateurs, en faisant apparaitre un message
à leur écran.

Puisque ce service n'offre aucune authentification,
un pirate peut l'utiliser pour pieger les utilisateurs
et leur faire faire quelque action (changer leur
mot de passe, quitter la console, etc...) en
envoyant un message semblant provenir de
l'administrateur.

Ce service peut aussi etre utilisé dans le cadre
d'une attaque par déni de service, en envoyant
continuellement des données sur les écrans
des utilisateurs, les empechant ainsi de travailler
correctement.

Solution : Désactivez ce service.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);



RPC_PROG = 100008;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_warning(port);
 else security_warning(port, protocol:"udp");
}
