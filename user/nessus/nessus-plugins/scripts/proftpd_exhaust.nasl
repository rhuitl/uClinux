#
# This script was written by Renaud Deraison <deraison@nessus.org>
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#
# References:
# Date:  Thu, 15 Mar 2001 22:30:24 +0000
# From: "The Flying Hamster" <hamster@VOM.TM>
# Subject: [SECURITY] DoS vulnerability in ProFTPD
# To: BUGTRAQ@SECURITYFOCUS.COM
#
#   Problem commands include:
#   ls */../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*/../*
#   ls */.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/*/.*/
#   ls .*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/.*./*?/
# 
#   Other commands of this style may also cause the same behavior; the exact
#   commands listed here are not necessary to trigger.
# 


if(description)
{
 script_id(10634);
 script_bugtraq_id(6341);
 script_version ("$Revision: 1.22 $");

 
 name["english"] = "proftpd exhaustion attack";
 name["francais"] = "proftpd exhaustion attack";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote FTP server seems to be vulnerable to an exhaustion
attack which may makes it consume all available memory on the remote
host when it receives the command :

	NLST /../*/../*/../*/../*/../*/../*/../*/../*/../*/../	
	

Solution : upgrade to ProFTPd 1.2.2 and modify your configuration
file to include :
	DenyFilter \*.*/
	
	
If you use another FTP server, contact your vendor.

Reference : http://online.securityfocus.com/archive/1/169069

Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur FTP distant semble vulnérable à une attaque lui faisant
consommer toute la mémoire du serveur FTP distant lorsqu'il reçoit
la commande :

	NLST /../*/../*/../*/../*/../*/../*/../*/../*/../*/../	

Solution : Si le serveur distant est ProFTPd, alors passez en version 1.2.2
sinon contactez votre vendeur pour un patch
Facteur de risque : Elevé";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the version of the remote proftpd",
                francais:"Détermine la version du proftpd distant");
 script_category(ACT_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
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
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login || safe_checks())
{
banner = get_ftp_banner ( port : port );
if ( ! banner ) exit(0);
if(egrep(pattern:"^220 ProFTPD ((1\.1\..*)|(1\.2\.(0|1)[^0-9]))", string:banner ))security_hole(port);
}
else
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
   pasv_port = ftp_pasv(socket:soc);
   soc2 = open_sock_tcp(pasv_port, transport:get_port_transport(port));
   if (! soc2)
	exit(0);
   req = string("NLST /../*/../*/../\r\n");
   send(socket:soc, data:req);
   code = ftp_recv_line(socket:soc);
   if(strlen(code))
     data = ftp_recv_listing(socket:soc2);
   else
     exit(0);
     
   if(("Permission denied" >< data) ||
      ("Invalid command" >< data))exit(0);
   if(egrep(string:data, pattern:"/\.\./[^/]*/\.\./"))
   {
    security_hole(port);
   }
   send(socket:soc, data:string("QUIT\r\n\r\n"));
   close(soc);
   close(soc2);
  }
 }
}
