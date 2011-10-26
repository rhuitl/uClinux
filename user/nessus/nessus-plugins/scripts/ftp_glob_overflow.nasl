#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10648);
 script_bugtraq_id(2548);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2001-0247");
 name["english"] = "ftp 'glob' overflow";
 name["francais"] = "Dépassement de buffer ftp par 'glob'";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by creating a huge directory structure and then
attempting to listing it using wildcards.
This is usually known as the 'ftp glob overflow' attack.

It is very likely that an attacker can use this
flaw to execute arbitrary code on the remote 
server. This will give him a shell on your system,
which is not a good thing.

Solution : upgrade your FTP server and/or libc
Consider removing directories writable by 'anonymous'.


Risk factor : High";
		 
		 
desc["francais"] = "
Il s'est avéré possible de faire planter le serveur
FTP distant en y créant une grande structure de
répertoires puis en la listant à l'aide de wildcards.

On appelle souvent ce problème le 'dépassement de buffer
ftpd par glob'.

Il est très probable qu'un pirate puisse utiliser ce
problème pour executer du code arbitraire sur le serveur
distant, ce qui lui donnera un shell sur votre système,
ce qui n'est pas une bonne chose.

Solution : mettez à jour votre serveur FTP ou libc, ou contactez
votre vendeur pour un patch.
	   
Facteur de risque : Elevé";
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP");
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);



if ( report_paranoia == 0 ) exit(0);



# First, we need access
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");



safe_checks = 0;
if(!login || !password || !wri || safe_checks())safe_checks = 1;


if(safe_checks)
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  vuln = 0;
  # FreeBSD
  if(egrep(pattern:"FTP server .version 6\.[0-9][0-9]",
  	  string:banner))vuln = 1;

  # NetBSD	  
  if(egrep(pattern:"NetBSD-ftpd ((19[0-9][0-9].*)|(2000)|(20010(([0-2])|3([0-1]|2[0-8]))))",
  	string:banner)) vuln = 1;
 
 
  # OpenBSD 
  
  # IRIX
  
  # MIT kerberos
  
  
  if(vuln)
  {
    desc = "
It may be possible to make the remote FTP server crash
by creating a huge directory structure and then
attempting to listing it using wildcards.
This is usually known as the 'ftp glob overflow' attack.

It is very likely that an attacker can use this
flaw to execute arbitrary code on the remote 
server. This will give him a shell on your system,
which is not a good thing.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade your FTP server and/or libc
Consider removing directories writable by 'anonymous'.


Risk factor : High";
  
  security_hole(port:port, data:desc);
  }
 }
 
 exit(0);
}




# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(login && wri)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  if(!egrep(pattern:"^250.*", string:b))exit(0);
  cwd = string("CWD ", crap(255), "\r\n");
  mkd = string("MKD ", crap(255), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely
  # 
  
  num_dirs = 0;
  
  for(i=0;i<5;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
 
  if(!egrep(pattern:"^257 .*", string:b) && !("ile exists" >< b)){
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 5;
	}
   else num_dirs = num_dirs + 1;   
  }
  
  
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  
  send(socket:soc, data:string("NLST ", wri, "/X*/X*/X*/X*/X*\r\n"));
  b = ftp_recv_line(socket:soc);
  if(!b){
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
	}
	
	
	
	
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  
  ftp_close(socket: soc);
  
  if(!num_dirs)exit(0);
  
  soc = open_sock_tcp(port);
  ftp_authenticate(socket:soc, user:login, pass:password);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  b = ftp_recv_line(socket:soc);
  
  for(i=0;i<num_dirs;i=i+1)
  {
   send(socket:soc, data:string("CWD ", crap(255), "\r\n"));
   b = ftp_recv_line(socket:soc); 
  }
  
  for(i=0;i<num_dirs + 1;i=i+1)
  {
   send(socket:soc, data:string("RMD ", crap(255), "\r\n"));
   b = ftp_recv_line(socket:soc);
   
   send(socket:soc, data:string("CWD ..\r\n"));
   b = ftp_recv_line(socket:soc);
  }
 }
}
}
