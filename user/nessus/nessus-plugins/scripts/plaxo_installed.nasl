#
# Written by:
# This script is Copyright (C) 2005 Tom Ferris
# GPLv2
# <tommy@security-protocols.com>
# 6/29/2005
# www.security-protocols.com
#

if(description)
{
 script_id(18591);
 script_version("$Revision: 1.1 $");

 name["english"] = "Plaxo Client Is Installed";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host has the Plaxo Client software installed. Plaxo is a contact manager.
Make sure its use is compatible with your corporate security policy.

Solution : Uninstall this software if it does not match your security policy
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Determines if Plaxo is installed";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tom Ferris <tommy@security-protocols.com>");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Plaxo/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
