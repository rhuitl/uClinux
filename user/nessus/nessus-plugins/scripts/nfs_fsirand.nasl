#
#
# Written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
#
# This is a _very_ old flaw
#
#

if(description)
{
 script_id(11353);
 script_bugtraq_id(32);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0167");
 
 name["english"] = "NFS fsirand";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote NFS server might allow an attacker to guess
the NFS filehandles, and therefore allow them to mount
the remote filesystems without the proper authorizations

Solution : See http://www.cert.org/advisories/CA-1991-21.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for NFS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 script_require_keys("rpc/portmap", "Host/OS/icmp");
 exit(0);
}




include("misc_func.inc");

os = get_kb_item("Host/OS/icmp");
if(!os) exit(0);
if("SunOS 4" >!< os) exit(0);

#----------------------------------------------------------------------------#
#                              Here we go                                    #
#----------------------------------------------------------------------------#

security_problem = 0;
list = "";
number_of_shares = 0;
port = get_rpc_port(program:100005, protocol:IPPROTO_TCP);
soc = 0;
if(!port)
{
 port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
 if(!port)exit(0);
}

security_hole(port);
