#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10318);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-b-0003");
 script_bugtraq_id(113, 2242, 599, 747);
 script_version ("$Revision: 1.42 $");
 script_cve_id("CVE-1999-0368", "CVE-1999-0878", "CVE-1999-0879", "CVE-1999-0950");
 
 name["english"] = "wu-ftpd buffer overflow";
 name["francais"] = "Dépassement de buffer wu-ftpd";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by creating a huge directory structure. 
This is usually called the 'wu-ftpd buffer overflow'
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
répertoires.
On appelle souvent ce problème le 'dépassement de buffer
wu-ftpd' bien qu'il concerne d'autres serveurs FTP.

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
		  
 script_dependencie("find_service.nes", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner || "wu-" >!< banner ) exit(0);

if(!safe_checks())
{
# First, we need access
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");

}
else
{
 login = 0;
 wri   = 0;
}


port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);


if(login && wri)
{
# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
 
  # We are in
 
  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(2540), "\r\n");
  mkd = string("MKD ", crap(2540), "\r\n");
  
  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune (or has a bigger than
  # 5Kb buffer, which is unlikely)
  # 
  
  num_dirs = 0;
    
  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);
 
  if(strlen(b) && !egrep(pattern:"^257 .*", string:b)){
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 20;
	}
  else
  {
  # No answer = the server has closed the connection. 
  # The server should not crash after a MKD command
  # but who knows ?
  
  
  if(!b){
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
	}
	
	
	
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  if(strlen(b) && !egrep(pattern:"^250 .*", string:b))
  	{
  	set_kb_item(name:"ftp/no_mkdir", value:TRUE);
	i = 20;
	}
  else
     num_dirs = num_dirs + 1;	
  
  #
  # See above. The server is likely to crash
  # here
  
  if(!b)
       {
  	security_hole(port);
	set_kb_item(name:"ftp/wu_ftpd_overflow", value:TRUE);
	exit(0);
       }
   }
  }
  ftp_close(socket: soc);
  
  
  #
  # Clean our mess
  #
  if(num_dirs == 0)exit(0);
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:password);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(2540),  "\r\n"));
   r = ftp_recv_line(socket:soc);
  }

  
  
  for(j=0;j<num_dirs+1;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(2540),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
  
  }
 }  
 exit(0);
}



if(banner)
{
  banner = tolower(banner);
  if("2.4.2" >< banner)
   {
    if((egrep(pattern:".*vr([0-9][^0-9]|10).*$",string:banner)) ||
       ("academ" >< banner)){
       		   report = string("It may be possible to make the remote FTP server crash\n",
		  		    "by creating a huge directory structure.\n",
				    "This is usually called the 'wu-ftpd buffer overflow'\n",
				     "even though it affects other FTP servers.\n\n",
				     "It is very likely that an attacker can use this\n",
				     "flaw to execute arbitrary code on the remote\n",
				     "server. This will give him a shell on your system,\n",
				     "which is not a good thing.\n",
				     "*** Warning : Nessus solely relied on the banner of this server\n\n",
				     "Solution : upgrade your FTP server.\n",
				     "Consider removing directories writable by 'anonymous'.\n",
				     "Risk factor : High");
       		security_hole(port:port, data:report);
	}
   }
}
