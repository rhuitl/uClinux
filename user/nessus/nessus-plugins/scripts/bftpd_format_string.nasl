#
# This script was written by Renaud Deraison <deraison@nessus.org>
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10568);
 script_version ("$Revision: 1.22 $");
 
 
 name["english"] = "bftpd format string vulnerability";
 name["francais"] = "bftpd format string vulnerability";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote ftp server does not sanitize properly the output
it gets from the NLST command.

It may be possible for a remote attacker to gain root access
thanks to this bug if he can write in any directory served
by this ftp daemon.

Solution : Upgrade your bftpd server to version 1.0.13

Reference : http://online.securityfocus.com/archive/1/149216

Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur FTP distant ne nettoye pas la sortie qu'il obtient
de la commande NLST.

Ce problème peut etre exploité par un pirate pour obtenir un
shell root sur cette machine.

Solution : Mettez à jour votre serveur bftpd en version 1.0.13
Facteur de risque : Sérieux";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a format string attack",
                francais:"Détermine si bftpd est vulnérable");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl" );
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
dir   = get_kb_item("ftp/writeable_dir");


port = get_kb_item("Services/ftp");
if(!port)port = 21;


if(!get_port_state(port))exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);

if(soc)
{
 if(login && dir && safe_checks() == 0 )
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = string("CWD ", dir, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  c = string("MKD Nessus_test\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^(257|451)", string:r))
  {
  c = string("CWD Nessus_test\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  
  c = string("MKD %p%p%p%p\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_line(socket:soc);
  port2 = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  if ( ! soc2 ) exit(0);
  
  c = string("NLST\r\n");
  send(socket:soc, data:c);
  r = ftp_recv_listing(socket:soc2);
  if(ereg(pattern:".*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9]*0x[a-f,A-F,0-9].*",
  	  string:r))security_hole(port);
  close(soc2);	  
  ftp_close(socket:soc);
  
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", dir, "/Nessus_test\r\n"));
  b = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("RMD %p%p%p%p\r\n"));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("CWD ..\r\n"));
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("RMD Nessus_test\r\n"));
  r = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  exit(0);
  }
   else {
    	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(0);
	}
 }
  else {
  	close(soc);
	soc = open_sock_tcp(port);
	if ( ! soc ) exit(0);
	}
 }
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-2]))",
  	 string:r)){
	 data = string(
"You are running a version of bftpd which is older or\n",
"as old as version 1.0.12.\n",
"These versions do not sanitize the NLST command output properly\n",
"and allow an intruder to execute arbitrary code through\n",
"it.\n\n",
"*** Note that Nessus did not log into this server\n",
"*** so it could not determine whether this server is really\n",
"*** vulnerable or not, so this message may be\n",
"*** a false positive because it relied on the server banner\n\n",
"Solution : upgrade to bftpd 1.0.13\n",
"Risk factor : High");
	 security_hole(port:port, data:data);
	 }
}
