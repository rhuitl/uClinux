#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22187);
 script_bugtraq_id(19389);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2006-3281");

 name["english"] = "Vulnerability in Windows Explorer Could Allow Remote Code Execution (921398)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web or
email client. 

Description :

The remote host is running a version of Windows which contains a flaw
in the Windows Explorer Drag & Drop handler.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message and save a file.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-045.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 921398";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.559", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Shell32.dll", version:"6.0.3790.2746", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1873", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Shell32.dll", version:"6.0.2900.2951", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.7105", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"921398") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


