#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22530);
 #script_bugtraq_id();
 script_version("$Revision: 1.2 $");
 script_cve_id("CVE-2006-4690");

 name["english"] = "Vulnerability in Windows Explorer Could Allow Remote Execution (923191)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web or
email client. 

Description :

The remote host is running a version of Windows which contains a flaw
in the Windows Explorer WebViewFolderIcon ActiveX control (Web View).

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-057.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 923191";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Comctl32.dll", version:"5.82.3790.583", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Comctl32.dll", version:"5.82.3790.2778", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Comctl32.dll", version:"5.82.2800.1891", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Comctl32.dll", version:"5.82.2900.2982", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Comctl32.dll", version:"5.81.4968.2500", min_version:"5.81.4900.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Comctl32.dll", version:"5.81.3900.7109", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"923191") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


