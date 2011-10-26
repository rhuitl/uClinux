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
# GPLv2
# 



############## description ################



# declare description
if(description)
{
	script_id(17342);
	script_version ("$Revision: 1.4 $");
	name["english"]="TFTP file detection (Cisco IOS)";
	script_name(english:name["english"]);
	desc["english"]= "
The remote host has a TFTP server installed that is serving one or 
more sensitive Cisco IOS files.\n\nThese files potentially include 
passwords and other sensitive information, so should not be exposed 
to unnecessary scrutiny.

Solution : If it is not required, disable the TFTP server. Otherwise 
restrict access to trusted sources only.

Risk Factor : High";
	script_description(english:desc["english"]);
	summary["english"]="Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS)";
	script_summary(english:summary["english"]);
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright 2005 Corsaire Limited.");
	family["english"]="Remote file access";
	script_family(english:family["english"]);
	script_dependencies('tftpd_detect.nasl', 'tftpd_backdoor.nasl');
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor');	# Not wise
 	exit(0);
}



############## declarations ################





############## script ################

include("tftp.inc");
include("misc_func.inc");

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

# Avoid FP
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

# initialise variables
local_var request_data;
local_var detected_files;
local_var file_name;
local_var file_list;
file_list=make_list('startup-config','network-confg','network.cfg','network.confg','cisconet-confg','cisconet.cfg','cisconet.confg','router-confg','router.config','router.cfg','ciscortr-confg','ciscortr.config','ciscortr.cfg','cisco-confg','cisco.confg','cisco.cfg');

if ( tftp_get(port:port,path:rand_str(length:10)) ) exit(0); 


# step through files
foreach file_name (file_list)
{
	# request file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		# add filename to response
		detected_files=raw_string(detected_files,file_name,"\n");
	}
}


# check if any files were detected
if(detected_files)
{
	description= "
The remote host has a TFTP server installed that is serving 
one or more sensitive Cisco IOS files.

The filenames detected are :

" + detected_files + "

These files potentially include passwords and other sensitive information, 
so should not be exposed to unnecessary scrutiny.

Solution : If it is not required, disable the TFTP server. Otherwise restrict 
access to trusted sources only.

Risk Factor : High";
	security_hole(data:description,port:port,proto:"udp");
}

exit(0);
