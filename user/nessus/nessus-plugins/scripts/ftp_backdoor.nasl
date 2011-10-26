#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10080);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-1999-0452");
 script_name(english:"Linux FTP backdoor",
 	     francais:"Backdoor dans un serveur FTP sous Linux");
	     

 script_description(english:"There is a backdoor in the old ftp daemons of
 Linux, which allows remote users to log in as 'NULL', with password 'NULL',
 and to get root privileges over FTP. 
 
 Solution : Update your FTP server to the latest version available.

 Risk factor : High",
 
 		   francais: "Il y a une backdoor dans les vieux serveurs FTP de Linux,
qui permet à un intrus de se logger en tant que 'NULL', avec le mot de passe 'NULL',
et d'obtenir ainsi les privilèges du root via sa connection FTP.

Solution : Mettez à jour votre serveur FTP.

Facteur de risque : Elevé");
		 
script_summary(english:"Checks for the NULL ftpd backdoor",
	       francais:"Détermine la présence de la backdoor NULL de ftpd");

 script_category(ACT_GATHER_INFO);
 

 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"NULL", pass:"NULL"))security_hole(port);
 }
}
