#
# This script was written by Alexis de Bernis <alexisb@nessus.org>
# 
#
# changes by rd :
# - rely on the banner if we could not log in
# - changed the description to include a Solution:
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10452);
 script_bugtraq_id(1387, 2240, 726);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-a-0004");
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0573", "CVE-1999-0997");
 
 name["english"] = "wu-ftpd SITE EXEC vulnerability";
 name["francais"] = "Vulnérabilité SITE EXEC de wu-ftpd";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote FTP server does not properly sanitize the argument of
the SITE EXEC command.
It may be possible for a remote attacker
to gain root access.

Solution : Upgrade your wu-ftpd server (<= 2.6.0 are vulnerable)
or disable any access from untrusted users (especially anonymous).

Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur ftp ne vérifie pas correctement les arguments de la
commande SITE EXEC.
Il est possible d'obtenir un accès root en exploitant ce bug.

Solution : Mettez à jour votre serveur wu-ftpd (<= 2.6.0 are vulnerables)
ou limitez l'accès aux utilisateurs de confiance (enlevez l'accès anonyme).

Facteur de risque : Sérieux";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the remote FTP server sanitizes the SITE EXEC command",
                francais:"Détermine si le serveur ftp distant vérifie la commande SITE EXEC");
 script_category(ACT_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2000 A. de Bernis",
                  francais:"Ce script est Copyright (C) 2000 A. de Bernis");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl",
 "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/wuftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");



port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


# Connect to the FTP server
soc = open_sock_tcp(port);
ftpport = port;
if(soc)
{
 if(login)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  # We are in
  c = string("SITE EXEC %p \r\n");
  send(socket:soc, data:c);
  b = recv(socket:soc, length:6);
  if(b == "200-0x") security_hole(ftpport);
  quit = string("QUIT\r\n");
  send(socket:soc, data:quit);
  r = ftp_recv_line(socket:soc);
  close(soc);
  exit(0);
  }
  else {
  	close(soc);
	soc = open_sock_tcp(ftpport);
	}
 }
  r = ftp_recv_line(socket:soc);
  close(soc);
  if(egrep(pattern:"220.*FTP server.*[vV]ersion wu-((1\..*)|(2\.[0-5]\..*)|(2\.6\.0)).*",
  	 string:r)){
	 data = string(
"You are running a version of wu-ftpd which is older or\n",
"as old as version 2.6.0.\n",
"These versions do not sanitize the user input properly\n",
"and allow an intruder to execute arbitrary code through\n",
"the command SITE EXEC.\n\n",
"*** Nessus did not log into this server\n",
"*** so it could not determine whether the option SITE\n",
"*** EXEC was activated or not, so this message may be\n",
"*** a false positive\n\n",
"Solution : upgrade to wu-ftpd 2.6.1\n",
"Risk factor : High");
	 security_hole(port:ftpport, data:data);
	 }
}
