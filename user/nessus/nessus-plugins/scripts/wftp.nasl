#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10305);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0200");
 
 name["english"] = "WFTP login check";
 name["francais"] = "Vérification de login de WFTP";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "This FTP server accepts
any login/password combination. This is a real
threat, since anyone can browse the FTP section
of your disk without your consent.

Solution : upgrade WFTP.

Risk factor : High";
 


 desc["francais"] = "Ce serveur FTP accepte
n'importe quelle paire login/password. 
C'est un vrai problème puisque n'importe
qui peut fouiner la section FTP de votre
disque dur, sans votre accord.

Solution : mettez à jour WFTP.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for any account";
 summary["francais"] = "Vérifie n'importe quel accompte";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "DDI_FTP_Any_User_Login.nasl");
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
  if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"bogusbogus", pass:"soogjksjka"))
  {
   security_hole(port);
  }
  close(soc);
 }
}
