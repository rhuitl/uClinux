#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10275);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0103");
 
 name["english"] = "Systat";
 name["francais"] = "Systat";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'systat' service provides useful information
to an attacker, such as which processes are running, who is running them,
and so on... It is highly recommended that you disable this service.

Risk factor : Low

Solution : comment out the 'systat' line in /etc/inetd.conf";

 desc["francais"] = "Le service 'systat' donne des informations utiles
aux crackers, comme, par exemple, quels sont les processus qui tournent,
qui les a lancé, etc... Il est recommandé que vous vous débarassiez de 
ce service.

Facteur de risque : Faible

Solution : désactivez ce service en mettant un diese (#) au debut de
 la ligne 'systat' dans /etc/inetd.conf";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for systat";
 summary["francais"] = "Vérifie la présence du service systat";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/systat", 11);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/systat");
if(!port)port = 11;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = recv_line(socket:soc, length:1024);
  if("pid" >< tolower(data) )security_warning(port);
  close(soc);
 }
}
