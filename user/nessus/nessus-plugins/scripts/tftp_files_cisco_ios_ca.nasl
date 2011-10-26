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
	script_id(17341);
	script_version ("$Revision: 1.2 $");
	name["english"]="TFTP file detection (Cisco IOS CA)";
	script_name(english:name["english"]);
	desc["english"]= "
The remote host has a TFTP server installed that is serving one or more 
sensitive Cisco IOS Certificate Authority (CA) files.

These files potentially include the private key for the CA so should be considered 
extremely sensitive and should not be exposed to unnecessary scrutiny.

Solution : If it is not required, disable the TFTP server. Otherwise restrict access to 
trusted sources only.
Risk Factor : High";
	script_description(english:desc["english"]);
	summary["english"]="Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS CA)";
	script_summary(english:summary["english"]);
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright 2005 Corsaire Limited.");
	family["english"]="General";
	script_family(english:family["english"]);
	script_dependencies("tftpd_detect.nasl");
	script_require_keys("Services/udp/tftp");
 	exit(0);
}



############## declarations ################







############## script ################

include("tftp.inc");

# initialise variables
local_var request_data;
local_var file_name;
local_var file_postfix;
local_var postfix_list;
local_var ca_name;
local_var detected_files;
local_var description;
postfix_list=make_list('.pub','.crl','.prv','.ser','#6101CA.cer','.p12');

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

# step through first nine certificate files
for(i=1;i<10;i++)
{
	# initialise variables
	file_name=raw_string(ord(i),'.cnm');
	
	# request numeric certificate file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		# initialise variables
		ca_name=eregmatch(string:request_data,pattern:'subjectname_str = cn=(.+),ou=');
		
		# check if cn is present in certificate file
		if(ca_name[1])
		{
			# add filename to response
			detected_files=raw_string(detected_files,file_name,"\n");
			
			# step through files
			foreach file_postfix (postfix_list)
			{
				# initialise variables
				file_name=raw_string(ca_name[1],file_postfix);

				# request certificate file
				if(request_data=tftp_get(port:port,path:file_name))
				{
					# add filename to response
					detected_files=raw_string(detected_files,file_name,"\n");
				}
			}
			
			break;
		}
	}
}

# check if any files were detected
if(detected_files)
{
	description= "
The remote host has a TFTP server installed that is serving one or 
more sensitive Cisco IOS Certificate Authority (CA) files.

The filenames detected are:

" +detected_files + "

These files potentially include the private key for the CA so should be 
considered extremely sensitive and should not be exposed to 
unnecessary scrutiny.

Solution : If it is not required, disable the TFTP server. Otherwise restrict 
access to trusted sources only.

Risk Factor : High";
	security_hole(data:description,port:port,proto:"udp");
}


exit(0);
