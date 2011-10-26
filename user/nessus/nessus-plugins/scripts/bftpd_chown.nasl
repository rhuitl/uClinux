#
# (C) Tenable Network Security
#


if(description)
{
 script_id(10579);
 script_bugtraq_id(2120);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0065", "CVE-2000-0943");
 
 name["english"] = "bftpd chown overflow";
 name["francais"] = "bftpd chown overflow";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote ftp server is vulnerable to a buffer overflow 
when issued too long arguments to the chown command.

It may be possible for a remote attacker to gain root access
thanks to this bug.

Solution : Upgrade your bftpd server to version 1.0.14 or
disable the option ENABLE_SITE in bftpd.conf
Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur FTP distant est vulnérable à une attaque par
dépassement de buffer lorsqu'il recoit un argument trop long
à la commande chown.

Ce problème peut etre exploité par un pirate pour obtenir un
shell root sur cette machine.

Solution : Mettez à jour votre serveur bftpd en version 1.0.14
ou changez la valeurd de l'option ENABLE_SITE en no dans bftpd.conf
Facteur de risque : High";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the remote bftpd daemon is vulnerable to a buffer overflow",
                francais:"Détermine si bftpd est vulnérable à un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl", "ftp_writeable_directories.nasl" );
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");



port = get_kb_item("Services/ftp");
if(!port)port = 21;


# Connect to the FTP server

include("ftp_func.inc");

if(safe_checks())login = 0;


if(login)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  req = string("SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A");
  req = req + string("\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  send(socket:soc, data:string("HELP\r\n"));
  r = ftp_recv_line(socket:soc);
  if(!r)security_hole(port);
  exit(0);
  }
   else {
    	ftp_close(socket: soc);
	}
}
 
banner = get_ftp_banner(port: port);
if(!banner)exit(0);
  
if(egrep(pattern:"220.*bftpd 1\.0\.(([0-9][^0-9])|(1[0-3]))",
  	 string:banner)){
	 data = string(
"You are running a version of bftpd which is older or\n",
"as old as version 1.0.13.\n",
"These versions are vulnerable to a buffer overflow when they\n",
"receive a tool long argument to the SITE CHOWN command, and this\n",
"allows an intruder to execute arbitrary code through\n",
"it.\n\n",
"*** Note that Nessus did not log into this server\n",
"*** so it could not determine whether this server is really\n",
"*** vulnerable or not, so this message may be\n",
"*** a false positive because it relied on the server banner\n\n",
"Solution : upgrade to bftpd 1.0.14 or disable the ENABLE_SITE option in bftpd.conf\n",
"Risk factor : High");
	 security_hole(port:port, data:data);
	 }

