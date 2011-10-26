#
# This script is released under the GPLv2
#

desc["english"] = "
Synopsis :

It is possible to access the remote NFS shares without having root privileges.

Description :

Some of the NFS shares exported by the remote server could be
mounted by the scanning host. An attacker may exploit this problem
to gain read (and possibly write) access to files on remote host.

Note that root privileges were not required to mount the remote shares. That is,
the source port to mount the shares was bigger than 1024.

Solution :

Configure NFS on the remote host so that only authorized hosts can mount
the remote shares.

The remote NFS server should prevent mount requests originating from a non-privileged port.

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:C)";


if(description)
{
 script_id(15984);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "User Mountable NFS shares";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for User Mountable NFS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison, modified 2004 Michael Stone");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
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
soc = open_sock_udp(port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
soc2 = open_sock_udp(port2);

if(!soc)exit(0);

foreach share (shares)
{
 fid = mount(soc:soc, share:share);
 if(fid)
 {
  content = readdir(soc:soc2, fid:fid);
  mountable += '+ ' + share + '\n' ;
  flag = 0;
  foreach c (content)
  {
   if(flag == 0){
   	mountable += ' + Contents of ' + share + ' : \n';
   	flag = 1;
	}
    mountable += ' - ' + c + '\n'; 
  }
  umount(soc:soc, share:share);
  mountable += '\n\n';
 }
}

close(soc);

if(mountable)
{
 report = desc["english"] + '\n\nPlugin output :\n\n' + string("The following NFS shares could be mounted without root privileges: \n", 
 		  mountable);
		 

 security_warning(port:2049, proto:"udp", data:report);
}		 
