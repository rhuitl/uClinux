#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11886);
 script_bugtraq_id(8830);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0006");
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2003-0660");
 
 name["english"] = "Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through web client.

Description :

The remote host contains a version of the Authenticode Verification module
which is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page and
entice a victim to visit this web page.
An attacker may also be able to exploit the vulnerability by sending a malicious
HTML email.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-041.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823182";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Cryptui.dll", version:"5.131.3790.67", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Cryptui.dll", version:"5.131.2600.1243", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Cryptui.dll", version:"5.131.2600.117", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Cryptui.dll", version:"5.131.2195.6758", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Cryptui.dll", version:"5.131.1878.14", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"KB823182") > 0 )
	security_hole(get_kb_item("SMB/transport"));

