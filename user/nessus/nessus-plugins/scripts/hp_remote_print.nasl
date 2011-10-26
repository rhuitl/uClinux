#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10104);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-1062");
 
 name["english"] = "HP LaserJet direct print";
 name["francais"] = "Impression directe HP LaserJet";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to connect
directly on this port, and it is very likely
that it is possible to make the printer print
the data we will sent to it, thus overriding
lpd authority.

This is a threat, because an attacker may connect
to this printer, force it to print pages of
garbage, and make it run out of paper. If
this printer is used relied on to print 
security logs, then this will be a problem.

Solution : filter incoming traffic to this port.

Risk factor : Low";


 desc["francais"] = "Il est possible de se connecter
à ce port, et il est très problable que les données
qui y seront envoyées seront imprimées par l'imprimante,
en outrepassant ainsi l'autorité de lpd.

C'est une menace, dans le sens où un pirate peut
se connecter à cette imprimante, et la forcer
à imprimer des pages de betises, faisant ensuite
manquer de papier à l'imprimante. Si celle-ci 
est utilisée pour imprimer des fichiers de
logs de sécurité, alors il y aura de gros problèmes,
puisqu'elle ne pourra pas remplir sa tache.

Solution : filtrez le traffic entrant vers ce port.

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if lpd is useless";
 summary["francais"] = "Vérifie si lpd est inutile";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "passwordless_hp_printer.nasl");
 script_require_keys("devices/hp_printer");
 script_require_ports(9099);
 exit(0);
}

#
# The script code starts here
#

hp = get_kb_item("devices/hp_printer");
if(hp)
{
 if(get_port_state(9099))
 {
  soc = open_sock_tcp(9099);
  if(soc){
  	security_warning(9099);
  	close(soc);
	}
 }
 if(get_port_state(9100))
 {
  soc = open_sock_tcp(9100);
  if(soc){
  	security_warning(9100);
	close(soc);
	}
 }
}
