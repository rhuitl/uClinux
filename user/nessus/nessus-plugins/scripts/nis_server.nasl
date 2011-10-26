#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10158);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0620");
 name["english"] = "NIS server";
 name["francais"] = "Serveur NIS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is a NIS server.  NIS is used to share password files among
the hosts of a given network, which must not be intercepted by an attacker.

Usually, the first step of their attack is to determine whether they are 
attacking a NIS server, which make the host a more valuable target.

Since we could determine that the remote host is a NIS server, they can 
determine too, which is not a good thing.


Solution : filter incoming TCP and UDP traffic to prevent them from connecting 
to the portmapper and to the NIS server.
Risk factor : Low";


 desc["francais"] = "
Le serveur distant est un serveur NIS.
NIS est utilisé pour partager des fichiers
de mots de passe entre les machines d'un réseau,
lesquels doivent rester hors de portée des pirates.

D'habitude, la premiere étape de l'attaque d'un
pirate est de déterminer si la machine attaquée
est un serveur NIS, ce qui en fait une cible
plus attractive.

Puisqu'il a été possible de determiner que le
système distant est un serveur NIS, il est probable
qu'ils peuvent le faire aussi, ce qui n'est
pas une bonne chose.

Solution : filtrez le traffic TCP et UDP entrant afin
d'empecher l'envoi de paquets vers le portmapper
RPC et le serveur NIS.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "NIS"; 
 family["francais"] = "NIS";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");


RPC_PROG = 100004;
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
