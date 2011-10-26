#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13637);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0019");
 script_bugtraq_id(10707);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0213");
 name["english"] = "Utility Manager Could Allow Code Execution (842526)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Local users can elevate their privileges.

Description :

The remote host is running a version of the Utility Manager which contains
a flaw which may allow a local attacker to execute arbitrary code on the host,
thus escalating his privileges and obtaining the full control of the remote
system.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms04-019.mspx

Risk factor : 

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-019 over the registry";

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

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Umandlg.dll", version:"1.0.0.5", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB842526") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
