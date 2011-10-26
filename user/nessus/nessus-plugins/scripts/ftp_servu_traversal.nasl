#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10565);
 script_bugtraq_id(2052);
 script_cve_id("CVE-2001-0054");
 script_version ("$Revision: 1.23 $");
 
 name["english"] = "Serv-U Directory traversal";
 name["francais"] = "Traversement de dossier Serv-U";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to break out of the remote
FTP chroot by appending %20s in the CWD command,
as in :

     CWD ..%20.
	

This problem allows an attacker to browse the entire remote
disk

Solution : Upgrade to Serv-U 2.5i
Risk factor : High";
 

 desc["francais"] = "
Il est possible de sortir de la prison du serveur Serv-U
distant en ajoutant des %20 dans la requete CWD, tel que dans :

	CWD %20..
	
Ce problème permet à un pirate d'acceder au disque distant dans son
intégralité.


Solution : Mettez Serv-U à jour en version 2.5i
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Traverses the remote ftp root";
 summary["francais"] = "traverses the remote ftp root";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(! login) login="ftp";
if (! pass) pass="test@nessus.com";

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:pass))
 {
  
  for(i=0;i<2;i=i+1)
  {
  data = string("CWD ..%20.\r\n");
  send(socket:soc, data:data);
  a[i] = ftp_recv_line(socket:soc);
  }
  
  if(a[0]==a[1])exit(0);

  if((egrep(pattern:".*to /..", string:a[0])) ||
     (egrep(pattern:".*to /[a-z]:/", string:a[1], icase:TRUE)) ||
     (egrep(pattern:"^550 /[a-z]:/.*", string:a[1], icase:TRUE)))
    	security_hole(port);

  exit(0);   
 }
ftp_close(socket: soc);


r = get_ftp_banner(port: port);
if(!r)exit(0);
 if(egrep(pattern:"^220 Serv-U FTP-Server v2\.(([0-4][0-9])|(5[a-h]))", string:r))
 {
 data = "
It is possible to break out of the remote
FTP chroot by appending %20 in the CWD command,
as in :

     CWD ..%20.
	

This problem allows an attacker to browse the entire remote
disk

*** Note : Nessus solely relied on the banner as it was not possible
*** to log into this server

Risk factor : High";
 	security_hole(port:port, data:data);
 }

