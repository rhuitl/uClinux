#
# This script was written by Renaud Deraison (deraison@cvs.nessus.org)
#
# This is the implementation of an oooold attack.
#

if(description)
{
 script_id(11357);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-1999-0166");
 
 name["english"] = "NFS cd ..";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote NFS server allows users to use a 'cd ..' command
to access other directories besides the NFS file system.

An attacker may use this flaw to read every file on this host

Solution : Create a dedicated partition for your NFS exports
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the NFS .. attack";
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

mountable = NULL;


list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);


port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_priv_sock_udp(dport:port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
soc2 = open_priv_sock_udp(dport:port2);

if(!soc || !soc2)exit(0);


foreach share (shares)
{
 fid = mount(soc:soc, share:share);
 if(fid)
 {
  dir1 = readdir(soc:soc2, fid:fid);
  fid2 = cwd(soc:soc2, fid:fid, dir:"..");
  dir2 = readdir(soc:soc2, fid:fid2);
  hash = make_list();
  
  foreach d (dir1)
  {
   hash[d] = 1;
  }
  
  foreach d (dir2)
  {
   if(!hash[d]){
   	report = 
"The remote NFS server allows users to use a 'cd ..' command
to access other directories besides the NFS file system.

The listing of " + share + ' is :\n';

  foreach d (dir1)
  {
   report += '- ' + d + '\n';
  }
  
report += string("\nAfter having sent a 'cd ..' request, the list of files is : \n");

 foreach d (dir2)
  {
   report += '- ' + d + '\n';
  }


report += "An attacker may use this flaw to read every file on this host

Solution : Contact your vendor for a patch
Risk factor : High";
   	security_hole(port:port, data:report);
	umount(soc:soc, share:share);
	exit(0);
	}
  }
   
  
  umount(soc:soc, share:share);
  close(soc);
  close(soc2);
  exit(0);
 }
}

close(soc);
close(soc2);
