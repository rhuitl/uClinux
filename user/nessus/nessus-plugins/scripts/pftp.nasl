#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# 
# Thanks to Overlord <mail_collect@gmx.net> for supplying me
# with the information for this problem as well as a copy of a
# vulnerable version of PFTP

if(description)
{
 script_id(10508);
 script_version ("$Revision: 1.7 $");
 
 
 name["english"] = "PFTP login check";
 name["francais"] = "Vérification de login de PFTP";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to log into the remote FTP server
as ' '/' '.

If the remote server is PFTP, then anyone
can use this account to read arbitrary files
on the remote host.

Solution : upgrade PFTP to version 2.9g
Risk factor : High";
 


 desc["francais"] = "
Il est possible de se logguer dans le serveur FTP distant
en tant que ' '/' '.

Si le serveur distant est PFTP, alors n'importe qui peut
utiliser ce compte pour lire des fichiers arbitraires sur 
la machine distante.

Solution : mettez à jour PFTP en version 2.9g
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for a blank account";
 summary["francais"] = "Vérifie la présence d'un compte vide";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl", 
	"ftp_kibuv_worm.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(get_port_state(port))
{
 if (get_kb_item("ftp/" + port + "/AnyUser") || get_kb_item('ftp/'+port+'/backdoor')) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:" ", pass:" "))
  {
   security_hole(port);
   set_kb_item(name:"ftp/pftp_login_problem", value:TRUE);
  }
  close(soc);
 }
}
