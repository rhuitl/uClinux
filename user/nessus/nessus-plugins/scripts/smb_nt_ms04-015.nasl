#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12235);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0015");
 script_bugtraq_id(10321);
 script_cve_id("CVE-2004-0199");
 script_version("$Revision: 1.9 $");
 name["english"] = "Microsoft Help Center Remote Code Execution (840374)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains bugs in the Microsoft Help and Support Center 
in the way it handles HCP URL validation. (840374)

An attacker could use this bug to execute arbitrary commands on the
remote host. To exploit this bug, an attacker would need to lure a user
of the remote host into visiting a rogue website or to click on a link
received in an email.

Solution : 

Microsoft has released a set of patches for Windows 2003 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-015.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-015 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Helprtr.exe", version:"5.2.3790.161", dir:"\pchealth\helpctr\binaries") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Helprtr.exe", version:"5.1.2600.1515", dir:"\pchealth\helpctr\binaries") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Helprtr.exe", version:"5.1.2600.137", dir:"\pchealth\helpctr\binaries") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB840374") > 0 )
	security_hole(get_kb_item("SMB/transport"));

