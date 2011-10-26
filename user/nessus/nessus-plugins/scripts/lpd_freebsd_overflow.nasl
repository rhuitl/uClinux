#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# This is a check for an OLD flaw
#

if(description)
{
   script_id(11354);
   script_version ("$Revision: 1.2 $");
   script_cve_id("CVE-1999-0299");
   name["english"] = "Buffer overflow in FreeBSD 2.x lpd";
  
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote lpd daemon seems to be vulnerable to a
buffer overflow when a host with a too long DNS host 
name connects to it.

*** Nessus solely relied on the version of the remote
*** operating system to issue an alert, so this
*** might be a false positive

Solution : Upgrade to FreeBSD 3.x
Risk factor : High";


   script_description(english:desc["english"]);
 
   summary["english"] = "Determines if lpd is running";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
   script_family(english:"Gain root remotely");
   script_require_ports("Services/lpd", 515);
   script_dependencies("find_service.nes", "os_fingerprint.nasl");
 
   exit(0);
}



#
# The code starts here
#

os = get_kb_item("Host/OS/icmp");
if(!os)exit(0);
if("FreeBSD 2" >!< os)exit(0);

port = get_kb_item("Services/lpd");
if(!port)port = 515;

soc = open_sock_tcp(port);
if(!soc)exit(0);
else security_hole(port);
