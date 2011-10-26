#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10556);
 script_bugtraq_id(301);
 script_cve_id("CVE-2001-0450");
 script_version ("$Revision: 1.23 $");
 
 name["english"] = "Broker FTP files listing";
 name["francais"] = "Broker FTP Files listing";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Some versions of Broker FTP (www.ftp-broker.com) allow
any anonymous user to browse the entire remote disk 
by issuing a command like :

	LIST C:\
	

Solution : upgrade to the latest version
Risk factor : High";


 desc["francais"] = "
Certaines versions de Broker FTP (www.ftp-broker.com) permettent
à des utilisateurs anonymes de browser sur le disque distant
en faisant la commande :

	LIST C:\
	
Solution : mettez à jour votre serveur FTP
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to get the listing of the remote root dir";
 summary["francais"] = "Essaye d'obtenir le listing du contenu de C:";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ftp");
if(!port) port = 21;

if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", get_host_name())))
{
 p = ftp_pasv(socket:soc);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(soc2)
 {
  s = string("LIST /\r\n");
  send(socket:soc, data:s);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      listing1 = ftp_recv_listing(socket:soc2);
  }
  close(soc2);
  r = ftp_recv_line(socket:soc);

  p = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if ( ! soc2 ) exit(0);

 
  s = string("LIST C:\\\r\n");
  send(socket:soc, data:s);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      r = ftp_recv_listing(socket:soc2);
      if(r && ( listing1 != r ) )
      {
	if("No such file or directory" >< r)exit(0);
      w = string("It was possible to get the listing of the remote root\n",
"directory by issuing the command\n\n",
"LIST C:\\\n",
"The data we could get is :\n",
r, "\n",
"An attacker may use this flaw to retrieve arbitrary files on this\n",
"server.\n",
"Solution : if you are using broker ftp, upgrade to the latest version, or\n",
"contact your vendor for a patch\n",
"Risk factor : High");
  security_hole(port:port, data:w);
     }
  }
 close(soc);
 close(soc2);
 }
}
}
