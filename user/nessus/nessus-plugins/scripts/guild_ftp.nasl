#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10471);
 script_bugtraq_id(1452);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0640");
 
 name["english"] = "Guild FTPd tells if a given file exists";
 name["francais"] = "Guild FTPd indique si un fichier existe";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote FTP server can be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. 

For instance, it is possible to determine the presence
of \autoexec.bat by requesting ../../../../autoexec.bat

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities.

Solution : Contact your vendor for the latest software release.
Risk factor : Low";
 


 desc["francais"] = "
Le serveur FTP distant peut etre utilisé pour determiner
si un fichier donné existe ou non, en ajoutant des
../ devant son nom.

Par exemple, il est possible de determiner la présence
de \autoexec.bat en demandant ../../../../autoexec.bat

Un pirate peut utiliser ce problème pour obtenir
plus d'informations sur ce système, comme la hiérarchie
de fichiers mise en place. Ce problème est d'autant plus
utile qu'il peut faciliter la mise en oeuvre de l'exploitation
d'autres vulnérabilités.

Solution : mettez votre serveur FTP à jour ou changez-en
Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Guild FTP check";
 summary["francais"] = "Vérifie la presence de Guild FTP";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port)) exit(0);

 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    pasv_port = ftp_pasv(socket:soc);
    soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
    req = string("RETR ../../../../../../nonexistent_at_all.txt\r\n");
  
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
  
    if("550 Access denied" >< r)
    {
    
     close(soc2);
     pasv_port = ftp_pasv(socket:soc);
     soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
     req = string("RETR ../../../../../../../../autoexec.bat\r\n");
     send(socket:soc, data:req);
     r =  recv_line(socket:soc, length:4096);
     r2 = recv_line(socket:soc, length:4096);
     r = string(r, r2);
     if("425 Download failed" >< r)security_warning(port);
     close(soc2);
    }
    ftp_close(socket: soc);
    exit(0);
    }
   }
  else
    {
     ftp_close(socket: soc);
    }   
  }
  
 #
 # We could not log in. Then we'll just attempt to 
 # grab the banner and check for version <= 0.97
 #
r = get_ftp_banner(port: port);
  if("GuildFTPD" >< r)
  {
   r = strstr(r, "Version ");
   if(egrep(string:r, pattern:".*Version 0\.([0-8].*|9[0-7]).*"))
  {
    security_warning(port);
  }
 }
