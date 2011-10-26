#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10070);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "Finger backdoor";
 name["francais"] = "Finger backdoor";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote finger daemon seems to be a backdoor, as it seems to react to the 
request :

		cmd_rootsh@target
		
If a root shell has been installed as /tmp/.sh, then this finger daemon is 
definitely a trojan, and this system has been compromised.

Solution: audit the integrity of this system, since it seems to have been 
compromised.

Risk factor : High";

 desc["francais"] = "Le daemon finger distant
semble être une backdoor, car il 
a l'air de ne pas etre insensible à
la requete :
		cmd_rootsh@cible

Si un shell root a été installé dans /tmp/.sh,
alors ce daemon est un cheval de troie, et
votre système a été compromis.

Solution: auditez l'intégrité de votre
système, car il semble avoir été corrompu.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Finger cmd_root@host backdoor";
 summary["francais"] = "Finger cmd_root@host backdoor";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#


include('global_settings.inc');

if ( report_paranoia < 2 )exit(0);

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("root\r\n");
  send(socket:soc, data:buf);
  data_root = recv(socket:soc, length:2048);
  close(soc);
  if(data_root)
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    buf = string("cmd_rootsh\r\n");
    send(socket:soc, data:buf);
    data_cmd_rootsh = recv(socket:soc, length:2048);
    close(soc);

    if(!data_cmd_rootsh)
    {
     buf = string("version\r\n");
     soc = open_sock_tcp(port);
     if(!soc)exit(0);
     send(socket:soc, data:buf);
     data_version = recv(socket:soc, length:2048);
     close(soc);

     if("CFINGERD" >< data_version) exit(0); #false positive
     if((data_root == data_version)) exit(0); #false positive, same answer all the time
     security_hole(port);
    }
   }
  }
 }
}
