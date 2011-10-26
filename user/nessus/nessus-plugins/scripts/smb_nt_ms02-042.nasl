#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11091);
 script_bugtraq_id(5480);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0720");
 name["english"] = "Flaw in Network Connection Manager Could Enable Privilege Elevation (Q326886)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The remote host contains a flaw in the Network Connection Manager
which may allow a local user to elevate his privileges.
To exploit this vulnerability a user need to send a specially crafted
code to the Network Manager handle to execute arbitrary code with the
privileges of the SYSTEM.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-042.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q326886, Network Elevated Privilege";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Netman.dll", version:"5.0.2195.5974", dir:"\system32") )
   security_note (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q326886") > 0 )
	security_hole(get_kb_item("SMB/transport"));

