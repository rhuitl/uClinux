#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10081);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0017");
 script_bugtraq_id(126);
 script_name(english:"FTP bounce check",
 	     francais:"Test FTP bounce");
 
  script_description(english:"
It is possible to force the FTP server to connect to third parties hosts by using 
the PORT command. 

This problem allows intruders to use your network resources to scan other hosts, making 
them think the attack comes from your network, or it can even allow them to go through 
your firewall.
   
Solution : Upgrade to the latest version of your FTP server, or use another FTP server.
Risk factor : Medium",
 
  francais:"Il est possible de forcer le serveur FTP à se connecter 
à des machines tierces, en utilisant la commande PORT. Ce problème 
permet à des intrus d'utiliser vos ressources réseaux pour scanner
d'autres machines, en faisant croire à celles-ci que l'attaque provient 
de chez vous, ou bien même de passer au travers de votre firewall.
  
Solution : Mettez à jour votre serveur FTP, ou utilisez-en un autre.

Facteur de risque : Moyen");
  

 script_summary(english:"Checks if the remote ftp server can be bounced",
 	        francais:"Détermine si le serveur ftp distant peut se connecter à des machines tierces");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 

 script_family(english:"FTP"); 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_kibuv_worm.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/ncftpd");
 exit(0);
}

#
# The script code starts here :
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  ip = get_host_ip();
  last = ereg_replace(string:ip,
  		    pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)$",
		    replace:"\1");
  last = int(last) + 1;
  ip = ereg_replace(string:ip, pattern:"\.", replace:",");
  ip = ereg_replace( pattern:"([0-9]*,[0-9]*,[0-9]*,)[0-9]*$",
  			replace:"\1",
			string:ip);
  ip = string(ip, last);			
  command = string("PORT ", ip, ",42,42\r\n");
  send(socket:soc, data:command);
  code = recv(socket:soc, length:4);
  if(code == "200 ")security_warning(port);
 }
 close(soc);
 }
} 


