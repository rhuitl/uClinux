#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10517);
 script_bugtraq_id(1666);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0843");
 
 name["english"] = "pam_smb / pam_ntdom overflow";
 name["francais"] = "Dépassement de buffer dans pam_smb / pam_ntdom";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote telnet server shut the connection abruptly when given
a long username followed by a password.

Although Nessus could not be 100% positive, it may mean that
the remote host is using an older pam_smb or pam_ntdom
pluggable authentication module to validate user credentials
against a NT domain.

Older version of these modules have a well known buffer 
overflow which may allow an intruder to execute arbitrary 
commands as root on this host. 

It may also mean that this telnet server is weak and crashes
when issued a too long username, in this case this host is
vulnerable to a similar flow.

This may also be a false positive.


Solution : 

 . if pam_smb or pam_ntdom is being used on this host, be sure to upgrade it 
   to the newest non-devel version.

 . if the remote telnet server crashed, contact your vendor for a patch

Risk factor : High";


 desc["francais"] = "
Le serveur telnet distant a brutalement coupé la connection lorsqu'un
nom d'utilisateur trop long, suivi d'un mot de passe, a été
envoyé.

Bien que Nessus ne puisse etre 100% catégorique à ce propos,
il se peut que l'hote distant utilise les modules d'authentification
pam_smb ou pam_ntdom pour valider les noms d'utilisateurs auprès
du domaine NT.

D'anciennes versions de ces modules possèdent un dépassement de
buffer permettant a un pirate d'executer du code arbitraire sur ces
machines.

Il se peut aussi que le serveur telnet distant soit mal écrit
et plante lorsqu'un argument trop long lui est donné - auquel
cas, ce serveur est vulnérable de la meme manière

Enfin, il peut s'agir d'une fausse alerte.


Solution :
	. si cet hote utilise pam_ntdom ou pam_smb, mettez
	  ces modules à jour
	  
	. si le serveur telnet distant a planté, contactez
	  votre vendeur et demandez un patch
	
	
Facteur de risque : Elevé";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to overflow the remote pam_smb";
 summary["francais"] = "Essaye de trop remplir les buffers de pam_smb";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
include('global_settings.inc');
if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
 {
  r = telnet_negotiate(socket:soc);
  if(!r)exit(0);
  if("HP JetDirect" >< r )exit(0);
  login = crap(length:1024, data:"nessus") + string("\r\n");
  send(socket:soc, data:login);
  r = recv(socket:soc, length:2048);
  if(!r)exit(0);
  send(socket:soc, data:string("pass\r\n"));
  r = recv(socket:soc, length:2048);
  close(soc);
  if(!r)
  {
  security_hole(port);
  }
 }
}
