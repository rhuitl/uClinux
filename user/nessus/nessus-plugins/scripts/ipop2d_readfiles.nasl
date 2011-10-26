#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Theory :
#
# - log into the remote server
# - fold /etc/passwd
# - read 1
# - retr
#
#
# We only check the banner for this flaw
#
#
 

if(description)
{
 script_id(10469);
 script_bugtraq_id(1484);
 script_version ("$Revision: 1.12 $");
 
 
 
 name["english"] = "ipop2d reads arbitrary files";
 name["francais"] = "ipop2d lit des fichiers arbitraires";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote pop2 server allows the reading of arbitrary
files for authenticated users, using the 'fold' command.

Solution : Contact your vendor for the latest software release.
Risk factor : High";


 desc["francais"] = "
Le serveur pop2 distant permet aux utilisateurs authentifiés
de lire des fichiers arbitraires à l'aide de la commande 'fold'.

Solution : mettez ce serveur à jour
Facteur de risque : Sérieux";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks if ipop2 allows the reading of any file";
 summary["francais"] = "si ipop2 permet de lire des fichiers arbitraires";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"],
	       francais:family["francais"]); 
 script_dependencie("find_service.nes");;
		       		     
 script_require_ports("Services/pop2", 109);
 exit(0);
}


port = get_kb_item("Services/pop2");
if(!port)port = 109;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 b = recv_line(socket:soc, length:1024);
 if(!strlen(b)){
 	close(soc);
	exit(0);
	}
 
 #
 # Versions up to 4.55 are vulnerable
 #
 if(ereg(pattern:"\+ POP2 .* v4\.([0-4][0-9] .*|[5][0-5]) .*",
  	 string:b))security_hole(port);
}

