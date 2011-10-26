

if(description)
{
 script_id(11358);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0168");
 
 name["english"] = "The remote portmapper forwards NFS requests";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote RPC portmapper forwards NFS requests made to it.

An attacker may use this flaw to make NFS mount requests which will appear 
to come from localhost and therefore override the ACLs set up for NFS.

Solution : Upgrade your portmapper to a newer version
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the portmapper proxying NFS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl", "showmount.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");


list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);


port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);

if(!soc)exit(0);

foreach share (shares)
{
 fid = mount(soc:soc, share:share);
 if(fid)
 {
  umount(soc:soc, share:share);
 }
 else {
  close(soc);
  port = get_kb_item("rpc/portmap");
  if(!port)port = 111;
  
  soc = open_priv_sock_udp(dport:port);
  req = rpclong(val:rand()) +
  	rpclong(val:0) +
	rpclong(val:2) +
	rpclong(val:100000) +
	rpclong(val:2) +
	rpclong(val:5) +
	rpclong(val:0) +
	rpclong(val:0) +
	rpclong(val:0) +
	rpclong(val:0) +
	rpclong(val:100005) +
	rpclong(val:1) +
	rpclong(val:1) +
	rpclong(val:strlen(share) + padsz(len:strlen(share)) + 4 ) +
	rpclong(val:strlen(share)) +
	share +
	rpcpad(pad:padsz(len:strlen(share)));
	
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if(!r)exit(0);
  if(str2long(val:r, idx:32) == 0)
  {
   security_hole(port);
   exit(0);
  }
 }
}
