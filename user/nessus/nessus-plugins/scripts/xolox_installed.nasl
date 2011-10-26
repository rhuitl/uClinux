#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11431);
# script_cve_id("CVE-MAP-NOMATCH");
 
 script_version("$Revision: 1.6 $");

 name["english"] = "XoloX is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using XoloX - a p2p software, 
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if XoloX is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/XoloX/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
