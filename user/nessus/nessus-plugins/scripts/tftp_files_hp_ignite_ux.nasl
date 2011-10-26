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
	script_id(19508);
	script_version ("$Revision: 1.3 $");
	name["english"]="TFTP file detection (HP Ignite-UX)";
	script_name(english:name["english"]);
	desc["english"]= "
The remote host has a TFTP server installed that is serving one or more 
sensitive HP Ignite-UX files.

These files potentially include sensitive information about the hardware and 
software configuration of the HPUX host, so should not be exposed to unnecessary 
scrutiny.

Solution: If it is not required, disable or uninstall the TFTP server. 
Otherwise restrict access to trusted sources only.
Risk factor: Medium";
	script_description(english:desc["english"]);
	summary["english"]="Determines if the remote host has sensitive files exposed via TFTP (HP Ignite-UX)";
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

# initialise variables

file_list=make_list('/var/opt/ignite/config.local','/var/opt/ignite/local/config','/var/opt/ignite/local/host.info','/var/opt/ignite/local/hw.info','/var/opt/ignite/local/install.log','/var/opt/ignite/local/manifest/manifest','/var/opt/ignite/recovery/makrec.append','/var/opt/ignite/server/ignite.defs','/var/opt/ignite/server/preferences');

# step through files
foreach file_name (file_list)
{
	# request file
	if(tftp_get(port:port,path:file_name))
	{
		security_warning(port:port,proto:"udp");
		exit(0);
	}
}
