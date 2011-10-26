#
#
# This NASL script was written by Martin O'Neal of Corsaire (http://www.corsaire.com)
# 
# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
# 



############## description ################



# declare description
if(description)
{
	script_id(19507);
	script_version ("$Revision: 1.3 $");
	name["english"]="TFTP file detection (Cisco CallManager)";
	script_name(english:name["english"]);
	desc["english"]="
The remote host has a TFTP server installed that is serving one or more Cisco 
CallManager files.
These files do not themselves include any sensitive information, but do identify 
the TFTP server as being part of a Cisco CallManager environment. The CCM TFTP 
server is an essential part of providing VOIP handset functionality, so should 
not be exposed to unnecessary scrutiny.

Solution: If it is not required, disable or uninstall the TFTP server. 
Otherwise restrict access to trusted sources only.
Risk factor: Low";
	script_description(english:desc["english"]);
	summary["english"]="Determines if the remote host has sensitive files exposed via TFTP (Cisco CallManager)";
	script_summary(english:summary["english"]);
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright 2005 Corsaire Limited.");
	family["english"]="General";
	script_family(english:family["english"]);
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/udp/tftp");

 	exit(0);
}



############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);




############## script ################

include("tftp.inc");

file_list = make_list('/MOH/SampleAudioSource.xml','RingList.xml','Annunciator.xml');

# step through files
foreach file_name (file_list)
{
	if( tftp_get(port:port,path:file_name) )
	{
		security_hole(port:port,proto:"udp");
		exit(0);
	}
}


