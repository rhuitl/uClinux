#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10276);
 script_bugtraq_id(225);
script_cve_id("CVE-1999-1201");
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "TCP Chorusing";
 name["francais"] = "TCP Chorusing";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Microsoft Windows 95 and 98 clients have the ability
to bind multiple TCP/IP stacks on the same MAC address,
simply by having the protocol added more than once
in the Network Control panel.

The remote host has several TCP/IP stacks with the
same IP bound on the same MAC address. As a result,
it will reply several times to the same packets,
such as by sending multiple ACK to a single SYN,
creating noise on your network. If several hosts
behave the same way, then your network will be brought
down.

Solution : Remove all the IP stacks except one in the remote
host.
Risk factor : Medium";



 desc["francais"] = "
Les clients Windows 95 et 98 ont la capacité de lier
plusieurs piles TCP/IP à la meme carte ethernet, simplement
en ajoutant le protocole réseau plus d'une fois dans
le panneau de controle 'Réseau'.

La machine distance a plusieurs piles TCP/IP ayant
la meme IP sur la meme adresse MAC. Par conséquent,
ce système répondra plusieurs fois aux requètes
qui lui sont faites, telles que répondre plusieurs
ACK à une requete SYN.

Si plusieurs systèmes fonctionnent de cette manière
sur votre réseau, alors il peut etre mis à genoux
très facilement.

Solution : retirez toutes les piles IP sauf une sur le système distant
Facteur de risque : moyen."; 


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Counts the number of ACKs to a SYN";
 summary["francais"] = "Compte le nombre de ACKs renvoyés à un SYN";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("os_fingerprint.nasl");
 script_exclude_keys("SMB/WindowsVersion");

 
 exit(0);
}

#
# The script code starts here
#

# do not test this bug locally

if(islocalhost())exit(0);

# broken
exit(0);

os = get_kb_item("Host/OS/icmp");
if(os)
{
 if("Windows 9" >!< os)exit(0);
}


port = get_host_open_port();
if(!port)port = 21;

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_TCP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

tcp = forge_tcp_packet(ip:ip, th_sport:10003, th_dport:port, 
		       th_win:4096,th_seq:rand(), th_ack:0,
		       th_off:5, th_flags:TH_SYN, th_x2:0,th_urp:0);
		       
filter = string("tcp and src host ", get_host_ip(), " and dst host ",
this_host(), " and src port ", port, " and dst port ", 10003);
r = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter);
if(r)
{
 r2 = pcap_next(pcap_filter:filter, timeout:5);
 if(r2)security_warning(port:0);
}

