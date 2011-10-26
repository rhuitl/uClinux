#
# This script was written by Chris Gragsone
# This script is for finding hosts that are running the 4553 parasite "mothership"
#



if(description) {
	script_id(11187);
	desc="
The backdoor '4553' seems to be installed on this host, which indicates
it has been compromised. 

Solution : re-install this host
Risk factor : Critical";
	

	
	script_version("$Revision: 1.6 $");
	# script_cve_id("CVE-MAP-NOMATCH");
	# NOTE: no CVE id assigned (jfs, december 2003)
	script_name(english:"4553 Parasite Mothership Detect");
	script_description(english:desc);
	script_summary(english:"Detects the presence of 4553 parasite's mothership");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is (C) 2002 Violating", 
		         francais:"Ce script est (C) 2002 Violating");
	script_family(english:"Backdoors");
	script_require_ports(21227, 21317);
	
	exit(0);
}



targets = make_list(21227, 21317);
foreach target (targets)
{
 if(get_port_state(target)) 
 {
 soc = open_sock_tcp(target);
 if(!soc)exit(0);
 send(socket:soc, data:"-0x45-");
 data = recv(socket:soc, length:1024);

 if(("0x53" >< data) || ("<title>UNAUTHORIZED-ACCESS!</title>" >< data)) 
  {
	security_hole(target);
  }
 }
}
