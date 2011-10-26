#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 edesc= "
The remote host answered to an ICMP_MASKREQ query and sent us its 
netmask <X>.

An attacker can use this information to understand how your network is set up
and how the routing is done. This may help him to bypass your filters.

Solution : reconfigure the remote host so that it does not answer to those 
requests.  Set up filters that deny ICMP packets of type 17.

Risk factor : Low";
if(description)
{
 script_id(10113);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0524");
 name["english"] = "icmp netmask request";
 name["francais"] = "requête icmp de masque de sous-réseau";
 
 script_name(english:name["english"], francais:name["francais"]);
 



 fdesc = "
La machine distante répond à une requête
ICMP_MASKREQ et nous a renvoyé son
masque de sous-réseau.

Un pirate peut utiliser cette information
pour mieux comprendre la configuration de
votre réseau et comment le routage fonctionne,
ce qui peut l'aider à outrepasser vos
filtres de paquets.

Solution : reconfigurez la machine distante
afin qu'elle ne réponde pas à ces requêtes.
Mettez en place des filtres qui rejettent
les paquets ICMP de type 17.

Facteur de risque : Faible";

 mydesc = ereg_replace(pattern:"<X>", replace:"", string:edesc);
 script_description(english:mydesc, francais:fdesc);
 
 summary["english"] = "Sends an ICMP_MASKREQ";
 summary["francais"] = "Envoie un ICMP_MASKREQ";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);

 
 exit(0);
}

#
# The script code starts here
#

if ( islocalhost() ) exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

icmp = forge_icmp_packet(ip:ip,icmp_type : 17, icmp_code:0,
                          icmp_seq : 1, icmp_id : 1, data:raw_string(0xFF, 0xFF, 0xFF, 0xFF));

filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());
for(i=0;i<5;i++)
{
r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
if(!isnull(r))
{
 type = get_icmp_element(icmp:r, element:"icmp_type");
 if(type == 18){
	data = get_icmp_element(icmp:r, element:"data");
	if ( strlen(data) != 4 ) exit(0);
	mask = "";
	for(i=0;i<4;i=i+1)
	{
   	mask = string(mask, ord(data[i]));
	if(i<3)mask = string(mask, ".");
	}
        mydesc = ereg_replace(pattern:"<X>", replace:string("(", mask, ")"), string:edesc);
	security_warning(protocol:"icmp", port:0, data:mydesc); 
	set_kb_item(name: 'icmp/mask_req', value: TRUE);
	}
 exit(0);
}
}

