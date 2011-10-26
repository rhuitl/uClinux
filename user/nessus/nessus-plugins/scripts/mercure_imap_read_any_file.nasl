#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10382);
 script_bugtraq_id(1144);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0318");
 

 
 name["english"] = "Atrium Mercur Mailserver";
 name["francais"] = "Atrium Mercur Mailserver";
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 
 desc["english"] = "
The remote imap server is Mercur Mailserver 3.20

There is a flaw in this server (present up to version 3.20.02)
which allow any authenticated user to read any file on the system.
This includes other users mailboxes, or any system file.

Warning : this flaw has not been actually checked but was deduced
          from the server banner
Solution : There was no solution ready when this vulnerability was written;
Please contact the vendor for updates that address this vulnerability.
Risk factor : High
See also : http://oliver.efri.hr/~crv/security/bugs/Others/mercur3.html";
 
 desc["francais"] = "
Le serveur imap distant est Mercur Mailserver 3.20

Il y a un bug dans ce serveur qui permet à n'importe quel
utilisateur valide de lire des fichiers arbitraires
sur ce système, ce qui inclut les boites aux lettres
des autres utilisateurs, mais aussi des fichiers systèmes.

Attention : ce problème n'a pas été testé mais a été déduit
            à partir de la bannière du serveur
Solution : aucune au moment de l'écriture de ce test (25 Avril 2000)
Voir aussi : http://oliver.efri.hr/~crv/security/bugs/Others/mercur3.html";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 summary["english"] = "mercure imap version check"; 
 summary["francais"] = "vérification de la version de mercure imap";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 	 	  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
	       
 script_dependencie("find_service.nes", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imap");
if(!port)port = 143;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  close(soc);
  if(!buf)exit(0);
  if(ereg(pattern:"^.*MERCUR IMAP4-Server.*v3\.20\..*$",
  	  string:buf))
	  	security_hole(port);	
	
 }
}
