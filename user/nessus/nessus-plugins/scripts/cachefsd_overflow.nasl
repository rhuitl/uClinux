#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10951);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0008");
 script_bugtraq_id(4631);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0084");
 
 name["english"] = "cachefsd overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The cachefsd RPC service is running on this port.

Multiple vulnerabilities exist in this service.  At least
one heap overflow vulnerability can be exploited remotely
to obtain root privileges by sending a long directory and
cache name request to the service.  A buffer overflow can
result in root privileges from local users exploiting the
fscache_setup function with a long mount argument.


Solaris 2.5.1, 2.6, 7 and 8 are vulnerable to this
issue. Sun patch 110896-02 is available for Solaris 8.
Other operating systems might be affected as well.


*** Nessus did not check for this vulnerability, 
*** so this might be a false positive

Solution : Deactivate this service - there is no patch at this time
           for pre-8 systems
            /etc/init.d/cachefs.daemon stop
          AND:
          Edit /etc/inetd.conf and disable the 100235/rcp service:
            #100235/1 tli rpc/tcp wait root /usr/lib/fs/cachefsd cachefsd
          Then kill -HUP the inetd process id.
          These activities may need to be repeated after every
          patch installation.

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the presence of a RPC service";
 summary["francais"] = "Vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely"; 
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia == 0 ) exit(0);


#
# This is kinda lame but there's no way (yet) to remotely determine if
# this service is vulnerable to this flaw.
# 
RPC_PROG = 100235;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port)
{
 if(tcp)security_hole(port);
 else security_hole(port, protocol:"udp");
}
