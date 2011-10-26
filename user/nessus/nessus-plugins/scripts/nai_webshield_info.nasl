#
# Written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details.
#

if(description)
{
  script_id(10424);
  script_bugtraq_id(1253);
 script_version ("$Revision: 1.10 $");
  script_cve_id("CVE-2000-0448");
  name["english"] = "NAI Management Agent leaks info";
  script_name(english:name["english"]);

  desc["english"] = "
The remote NAI WebShield SMTP Management tool
gives away its configuration when it is issued
the command :

	GET_CONFIG

This may be of some use to an attacker who will
gain more knowledge about this system.

Solution : filter incoming traffic to this port. You
may also restrict the set of trusted hosts in the
configuration console :
	- go to the 'server' section
	- select the 'trusted clients' tab
	- and set the data accordingly

Risk factor : Low";	

 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote NAI WebShield SMTP Management trusts us"; 
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(9999);
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
     close(soc);
     if("SMTP_READ_PORT" >< r)
     {
       set_kb_item(name:"nai_webshield_management_agent/available", value:TRUE);
       security_warning(port);
     }
   }
}
