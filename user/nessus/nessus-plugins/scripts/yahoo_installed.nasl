#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11432);
 script_bugtraq_id(2299, 4162, 4163, 4164, 4173, 4837, 4838, 5579, 6121);
 script_cve_id("CVE-2002-0320", "CVE-2002-0321", "CVE-2002-0031", "CVE-2002-0032", "CVE-2002-0322");  
 
 script_version("$Revision: 1.10 $");

 name["english"] = "Yahoo!Messenger is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
Yahoo!Messenger - an instant messenging software, which may not be suitable 
for a business environment - is installed on the remote host. If its use
is not compatible with your corporate policy, you should de-install it.

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Yahoo!Messenger is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Yahoo! Messenger/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
