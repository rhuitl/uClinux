#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11428);
 script_bugtraq_id(5677, 5733, 5755, 5765, 5769, 5775, 5776, 5777, 5783);

 # no cve_id
 
 script_version("$Revision: 1.6 $");

 name["english"] = "Trillian is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Trillian - a p2p software, 
which may not be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Trillian is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}



rootfile = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Trillian/DisplayName");

if(rootfile) security_note(get_kb_item("SMB/transport")); 
