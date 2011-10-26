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
	script_id(19510);
	script_bugtraq_id(14571);
	script_cve_id("CVE-2004-0952");
	script_version ("$Revision: 1.4 $");


	name["english"]="TFTP directory permissions (HP Ignite-UX)";
	script_name(english:name["english"]);
	desc["english"] = "
The remote host has a vulnerable version of the HP Ignite-UX application 
installed that exposes a world-writeable directory to anonymous TFTP access.

Solution: Upgrade to a version of the Ignite-UX application that does not exhibit 
this behaviour. If it is not required, disable or uninstall the TFTP server. 
Otherwise restrict access to trusted sources only.

See also : http://www.corsaire.com/advisories/c041123-002.txt

Risk factor: High";
	script_description(english:desc["english"]);
	summary["english"]="Determines if the remote host has writeable directories exposed via TFTP (HP Ignite-UX)";
	script_summary(english:summary["english"]);
	script_category(ACT_DESTRUCTIVE_ATTACK); # Intrusive
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

# initialise test
file_name='/var/opt/ignite/nessus_tftp_test_'+rand();
if(tftp_put(port:port,path:file_name))
	security_hole(port:port,proto:"udp");

