# This script was written by Jason Haar <Jason.Haar@trimble.co.nz>
#
#
if(description)
{
 script_id(12215);
 script_version("$Revision: 1.3 $");
 name["english"] = "Sophos Anti Virus Check";
 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks that the remote host has the Sophos Antivirus installed 
and that it is running.

Solution : Make sure Sophos is installed and using the latest VDEFS.
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that the remote host has Sophos Antivirus installed and then makes sure the latest Vdefs are loaded."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Jason Haar"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/Registry/Enumerated", "SMB/svcs");
 exit(0);
}



services = get_kb_item("SMB/svcs");
if ( ! services ) exit(0);

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Sophos/SweepNT/Version");
if ( ! version ) exit(0);

#
# Checks to see if the service is running 
#
if("[SWEEPSRV]" >!< services) {
	report = "
The remote host has the Sophos antivirus installed, but it
is not running.

As a result, the remote host might be infected by viruses received by
email or other means. 

Solution : Enable the remote AntiVirus and configure it to check for updates regularly.
Risk factor : Medium";
	security_warning(port:port, data:report);
	}
