#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10088);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0527");
 name["english"] = "Writeable FTP root";
 name["francais"] = "On peut écrire sur la racine du répertoire FTP";
 name["portugues"] = "Escrita permitida no diretório raiz do servidor FTP";
 script_name(english:name["english"], francais:name["francais"], portugues:name["portugues"]);
 
 desc["english"] = "It is possible to write on the root directory
of this remote anonymous FTP server. This allows
an attacker to upload '.rhosts' or '.forward' files, 
or to turn your FTP server in to a warez server.

Solution : chown root ~ftp && chmod 0555 ~ftp.

Risk factor : High";

 desc["francais"] = "Il est possible d'écrire à la racine
de ce serveur FTP anonyme. Cela permet à des
pirates d'uploader des fichiers '.rhosts' ou
'.forward', ou alors de transformer votre
serveur FTP en serveur de warez.

Solution : chown root ~ftp && chmod 0555 ~ftp.

Facteur de risque : Sérieux";


 desc["portugues"] = "É possível escrever no diretório raiz deste
servidor FTP logando como anonymous. Isto possibilita à crackers
fazerem upload de arquivos '.rhosts' ou '.forward', ou transformar
seu servidor FTP num servidor warez.

Solução : chown root ~ftp && chmod 0555 ~ftp.

Fator de risco: Sério";


 script_description(english:desc["english"], francais:desc["francais"],
		portugues:desc["portugues"]);
 
 summary["english"] = "Attempts to write on the remote root dir";
 summary["francais"] = "Essaye d'écrire à la racine";
 summary["portugues"] = "Tentativa de escrever no diretório raiz do servidor FTP remoto";

 script_summary(english:summary["english"], francais:summary["francais"],
 		portugues:summary["portugues"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		portugues:"Este script é Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 family["portugues"] = "FTP";
 script_family(english:family["english"], francais:family["francais"],
 		portugues:family["portugues"]);		
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
  data = string("CWD /\r\n");
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  pasv = ftp_pasv(socket:soc); 
  data = string("STOR nessus_test\r\n");
  send(socket:soc, data:data);
  r = recv_line(socket:soc, length:3);
  if((r == "425")||(r == "150"))
  {
   data = string("DELE nessus_test\r\n");
   send(socket:soc,data:data);
   security_hole(port);
   wri = get_kb_item("ftp/writeable_dir");
   if(!wri)set_kb_item(name:"ftp/writeable_dir", value:"/");
   set_kb_item(name:"ftp/writeable_root", value:TRUE);
  }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
close(soc);
}
}
