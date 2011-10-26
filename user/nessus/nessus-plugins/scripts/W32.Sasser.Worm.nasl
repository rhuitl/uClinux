
exit(0); # moved into smb_virii.nasl

# This script was written by Jeff Adams <jadams@netcentrics.com>
# This script is Copyright (C) 2004 Jeff Adams


if(description)
{
 script_id(12220);
 
 script_version("$Revision: 1.4 $");

 name["english"] = "W32.Sasser.Worm";

 script_name(english:name["english"]);
 
 desc["english"] = "
W32.Sasser.Worm Infection.
W32.Sasser.Worm is a worm that attempts to exploit the MS04-011 vulnerability. 
It spreads by scanning randomly-chosen IP addresses for vulnerable systems.
This plugin checks for W32.Sasser.Worm, W32.Sasser.B.Worm 
and W32.Sasser.Ci.Worm Variants.

Solution : Use Latest Anti Virus to clean machine. Virus Definitions and removal tools are being released as of 05/01/04

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Machine is infected with W32.Sasser.Worm";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		    "smb_login.nasl","smb_registry_access.nasl",
		    "smb_registry_full_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");

virus1 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", item:"avserve.exe");
virus2 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", item:"avserve2.exe");

if(virus1 || virus2)
 {
  security_hole(get_kb_item("SMB/transport"));
 }

exit(0);

