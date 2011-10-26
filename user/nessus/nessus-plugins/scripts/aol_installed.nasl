# This script was written by Jeff Adams <jeffrey.adams@hqda.army.mil>
# This script is Copyright (C) 2003 Jeff Adams


if(description)
{
 script_id(11882);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "AOL Instant Messenger is Installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using AOL Instant Messenger (AIM). AIM has been associated 
with multiple security vulnerabilities in the past. This software is not 
suitable for a business environment. 

Solution : Uninstall the software
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if AOL Instant Messenger is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/AOL Instant Messenger/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
