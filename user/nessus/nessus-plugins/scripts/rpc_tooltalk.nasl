#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10239);
 script_bugtraq_id(122, 641);
 script_version ("$Revision: 1.24 $");
 if(defined_func("script_xref"))script_xref(name:"CERT", value:"CA-98.11");
 script_cve_id("CVE-1999-0003","CVE-1999-0693");
 
 name["english"] = "tooltalk service";
 name["francais"] = "Service tooltalk";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The tooltalk RPC service is running.  

A possible implementation fault in the ToolTalk object database server may allow an
attacker to execute arbitrary commands as root.

*** This warning may be a false positive since the presence of this vulnerability is only 
**** accurately identified with local access.
    
Solution : Disable this service.
See also : CERT Advisory CA-98.11
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 if ( ! defined_func("bn_random") ) 
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
 else
 	script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl", "solaris26_105802.nasl", "solaris26_x86_105803.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia == 0 ) exit(0);


if ( get_kb_item("BID-122") ) exit(0);
version = get_kb_item("Host/Solaris/Version");
if ( version && ereg(pattern:"5\.[0-6][^0-9]", string:version) ) exit(0);
else {
	version = get_kb_item("Host/OS/icmp");
	if ( version && ereg(pattern:"Solaris ([7-9]|1[0-9])", string:version) ) exit(0);
}


RPC_PROG = 100083;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}



if(port)
{
 vulnerable = 0;
 os = get_kb_item("Host/OS/icmp");
 if(!os)vulnerable = 1;
 else
 {
   if(ereg(pattern:"Solaris|HP-UX|IRIX|AIX", string:os))
   {
   if(ereg(pattern:"Solaris 2\.[0-6]", string:os))vulnerable = 1;
   if(ereg(pattern:"HP-UX.*(10\.[1-3]0|11\.0)", string:os))vulnerable = 1;
   if(ereg(pattern:"AIX 4\.[1-3]", string:os))vulnerable = 1;
   if(ereg(pattern:"IRIX (5\..*|6\.[0-4])", string:os))vulnerable = 1;
   }
   else vulnerable = 1; # We don't know
 }

 if(vulnerable)
 {
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
 }
}
