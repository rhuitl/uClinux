#
# This script was written by Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to enumerate installed software.

Description :

This plugin lists software installed on the remote host by crawling
the registry entries in :
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall

Solution : 

Remove software that are not compliant with your company policy.

Risk factor : 

None";


if(description)
{
 script_id(20811);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Software Enumeration (via SMB)";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates the list of remote software";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = kb_smb_transport ();

softwares = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(softwares))
  exit (0);

list = NULL;
foreach software (keys(softwares))
{
 name = ereg_replace (pattern:"(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/.*/)DisplayName", string:software, replace:"\1");
 version = get_kb_item (string(name, "DisplayVersion"));

 list += string (softwares[software]);

 if (!isnull(version))
   list += string ("  [version ", version, "]");

 list += string ("\n");
}

if(list)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following software are installed on the remote host:\n\n",
		list);

 security_note(data:report, port:port);
}
