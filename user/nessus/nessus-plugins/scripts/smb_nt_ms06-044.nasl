#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22186);
 script_bugtraq_id(19417);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2006-3643");

 name["english"] = "Vulnerability in Microsoft Management Console Could Allow Remote Code Execution (917008)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web or
email client. 

Description :

The remote host is running a version of Windows which contains a flaw
in the Management Console.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
web site or view a specially-crafted email message. 

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/Bulletin/MS06-044.mspx

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 917088";

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


if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Mmcndmgr.dll", version:"5.0.2195.7102", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"917008") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


