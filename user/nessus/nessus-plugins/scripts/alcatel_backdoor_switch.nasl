#
# This script was written by deepquest <deepquest@code511.com>
# 
# See the Nessus Scripts License for details
#
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com> 
#    who wrote a duplicate of this script
#
#----------
# XXXX Untested!

if(description)
{
 script_id(11170);
 script_bugtraq_id(6220);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1272");

 name["english"] = "Alcatel OmniSwitch 7700/7800 switches backdoor";
 name["francais"] = "Porte derobee dans les switchs Alcatel OmniSwitch 7700/7800";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host seems to be a backdoored
Alcatel OmniSwitch 7700/7800.

An attacker can gain full access to any device
running AOS version 5.1.1, which can result in,
but is not limited to, unauthorized access,
unauthorized monitoring, information leakage,
or denial of service. 

Solution : Block access to port 6778/TCP or update to 
AOS 5.1.1.R02 or AOS 5.1.1.R03.

See also: http://www.cert.org/advisories/CA-2002-32.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of backdoor in Alcatel  7700/7800 switches ";
 summary["francais"] = "Determines la presence d'une porte derobee dans les switchs Alcatel OmniSwitch 7700/7800";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (c) 2002 deepquest",
		francais:"Ce script est Copyright (c) 2002 deepquest");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 
 exit(0);
}


include("telnet_func.inc");
include("misc_func.inc");

port = 6778;
p = known_service(port:port);
if(p && p != "telnet" && p != "aos")exit(0);



if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = get_telnet_banner(port:port);
 if(data)
  {
  security_note(port:port,data:string("The banner:\n",data,"\nshould be reported to deraison@nessus.org\n"));
  security_hole(port);
  register_service(port: port, proto: "aos");
  }
 }
}
