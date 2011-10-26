#
# (C) Tenable Network Security
#


if (description) {
  script_id(18174);
  script_version("$Revision: 1.2 $");

  name["english"] = "ICUII Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows host contains a video chat application.

Description :

ICUII is installed on the remote host.  ICUII is a video chat package
for Windows that supports both 'family-oriented' and 'adult' themes. 

See also : 

http://www.icuii.com/

Solution :

Make sure use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for ICUII";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of ICUII.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ICUII/DisplayName";
if (get_kb_item(key)) security_note(port);
