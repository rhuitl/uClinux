#
# Josh Zlatin-Amishav GPLv2
#
# 

if (description) {
  script_id(19585);
  script_version("$Revision: 1.1 $");

  name["english"] = "Mercora IMRadio Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Mercora IMRadio is installed on the remote host.  Mercora is an Internet
radio tuner that also provides music sharing, instant messaging, chat,
and forum capabilities.  This software may not be suitable for use in a
business environment. 

See also : http://www.mercora.com/default2.asp
Risk Factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Mercora IMRadio";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005 Josh Zlatin-Amishav");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Look in the registry for evidence of Mercora.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Mercora/DisplayName";
if (get_kb_item(key)) security_note(port);
