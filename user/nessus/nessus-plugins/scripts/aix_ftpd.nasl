#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10009);
 script_bugtraq_id(679);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-0789");
 name["english"] = "AIX FTPd buffer overflow";
 name["francais"] = "Dépassement de buffer dans ftpd d'AIX";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server
crash by issuing this command :

	CEL aaaa[...]aaaa

This problem is known has the 'AIX FTPd' overflow and
may allow the remote user to easily gain access to the 
root (super-user) account on the remote system.

Solution : If you are using AIX FTPd, then read
IBM's advisory number ERS-SVA-E01-1999:004.1,
or contact your vendor for a patch.

Risk factor : High";
		 
		 
desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
FTP distant en lancant la commande :

CEL aaa[...]aaa

Ce problème est connu sous le nom de 'dépassement de buffer
de aix ftpd' et permet à un pirate de passer root sur
ce système sans grande difficulté.

Solution : si vous utilisez le ftpd de AIX, lisez
l'advisory d'IBM numéro ERS-SVA-E01-1999:004.1
ou contactez votre vendeur et demandez un patch.

Facteur de risque : elevé";	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote FTPd can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis à un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP", francais:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/msftpd","ftp/vxftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(0);

if ( ! egrep(pattern:".*FTP server .Version 4\.*", string:banner) ) exit(0);

if(safe_checks())
{
 
 if(egrep(pattern:".*FTP server .Version 4\.3.*",
   	 string:banner)){
	 desc = "
It may be possible to make the remote FTP server
crash by issuing this command :

	CEL aaaa[...]aaaa
	
This problem is known as the 'aix ftpd' overflow and
may allow the remote user to gain root easily.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : if you are using AIX ftpd, then read
IBM's advisory number ERS-SVA-E01-1999:004.1,
or else contact your vendor for a patch.

Risk factor : High";
  
  	 security_hole(port:port, data:desc);
	 } 
 exit(0);
}

if(get_kb_item("ftp/vxworks"))exit(0); # seperate test for vxworks

soc = open_sock_tcp(port);
if(soc)
{
  buf = ftp_recv_line(socket:soc);
  if(!buf){
 	close(soc);
	exit(0);
	}

  buf = string("CEL a\r\n");
  send(socket:soc, data:buf);
  r = ftp_recv_line(socket:soc);
  if(!r)exit(0);
  buf = string("CEL ", crap(2048), "\r\n");
  send(socket:soc, data:buf);
  b = ftp_recv_line(socket:soc);
  if(!b)security_hole(port);
  ftp_close(socket: soc);
}

