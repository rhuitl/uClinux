#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10152);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0660");
 
 name["english"] = "NetBus 2.x";
 name["francais"] = "NetBus 2.x";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
NetBus Pro is installed.


NetBus is a remote administration tool that can
be used for malicious purposes, such as sniffing
what the user is typing, its passwords and so on.

An attacker may have installed it to control
hosts on your network.

Solution : see http://www.netbus.com
Risk factor : High";


 desc["francais"] = "
NetBus Pro est installé.

NetBus est un programme d'administration à distance
qui peut etre utilisé pour sniffer les données entrées
par l'utilisateur, ses mots de passe, etc...

Un pirate peut avoir installé ce programme pour controller
les machines de votre réseau.

Solution : cf http://www.netbus.com

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the presence of NetBus Pro";
 summary["francais"] = "Détermine la présence de NetBus Pro";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("os_fingerprint.nasl");
 script_require_ports(20034);
 exit(0);
}

#
# The script code starts here
#

os = get_kb_item("Host/OS/icmp");
if(os)
{
 if("Windows" >!< os)exit(0);
}

#
# Reverse-engineered data. Not very meaningful.
# Thanks to Jean Marc Herraud <herraud@rennes.enst-bretagne.fr>
#

s = raw_string(0x42, 0x4e, 0x1f, 0x00, 0x02, 0x00, 0xdc, 0x33, 
               0x05, 0x00, 0x41, 0x0c, 0x69, 0x1f, 0x5d, 0x28, 
	       0x5b, 0x95, 0x9c, 0xad, 0x95, 0xa8, 0xe6, 0x28 ,
	       0xfd ,0x1d, 0xfa, 0x10, 0x55, 0x83, 0xe2);

r = raw_string(0x42, 0x4e, 0x10, 0x00, 0x02, 0x00);

if(get_port_state(20034))
{	    
 soc = open_sock_tcp(20034);
 if(soc)
 {
 send(socket:soc, data:s, length:31);
 r2 = recv(socket:soc, length:6);
 if(r2){
   	flag = 0;
 	for(i=0;i<6;i=i+1)
	{
	 if(!(r[i]==r2[i])){
	 	flag = flag + 1;
		exit(0);
		}
	}
	if(!flag)security_hole(20034);
      } 
 close(soc);
 }
}
