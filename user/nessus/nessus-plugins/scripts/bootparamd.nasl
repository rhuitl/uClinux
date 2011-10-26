#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10031);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0647");
 name["english"] = "bootparamd service";
 name["francais"] = "Service bootparamd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The bootparamd RPC service is running. 
It is used by diskless clients to get
the necessary information needed to
boot properly.

If an attacker uses the BOOTPARAMPROC_WHOAMI
and provides the correct address of the client,
then he will get its NIS domain back from
the server. Once the attacker discovers the NIS domain
name, it may easily get your NIS password
file.


Solution : filter incoming traffic to prevent connections
to the portmapper and to the bootparam daemon,
or deactivate this service if you do not use it.

Risk factor : High";


 desc["francais"] = "
Le service RPC bootparamd tourne.
Il est utilisé par des stations sans disque
pour obtenir les informations nécéssaire à
leur phase de démarrage.

Si un pirate utilise la fonction BOOTPARAMPROC_WHOAMI
et donne la bonne adresse du client, alors il peut
obtenir le nom de votre domaine NIS. Une fois
que le nom du domaine NIS est connu, il est
facile de récuperer le fichier de mot de passe
NIS.


Solution : filtrez le traffic entrant en direction
du serveur bootparamd et du portmapper RPC. Si vous
n'utilisez pas bootparamd, alors désactivez-le.

Facteur de risque : Sérieux";


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


RPC_PROG = 100026;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 set_kb_item(name:"rpc/bootparamd", value:TRUE);
 if(tcp)security_warning(port);
 else security_warning(port, protocol:"udp");
}
