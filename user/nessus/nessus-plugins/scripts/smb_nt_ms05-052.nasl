#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20005);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(15061);
 script_cve_id("CVE-2005-2127");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0028");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0032");
 
 script_version("$Revision: 1.11 $");
 name["english"] = "Cumulative Security Update for Internet Explorer (896688)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains a version of the Internet Explorer which is
vulnerable to a security flaw (COM Object Instantiation Memory Corruption
Vulnerability) which may allow an attacker to execute arbitrary code on the
remote host by constructing a malicious web page and entice a victim 
to visit this web page.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP SP2 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-052.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896688";

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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
 
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.418", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2541", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2769", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1522", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1522", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3833.200", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 else
   set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB896688", value:TRUE);
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else 
if ( hotfix_missing(name:"896688") > 0 && 
     hotfix_missing(name:"905915") > 0 &&
     hotfix_missing(name:"910620") > 0 &&
     hotfix_missing(name:"912812") > 0 &&
     hotfix_missing(name:"918899") > 0 &&
     hotfix_missing(name:"916281") > 0 )
{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( ( "896688" >!< minorversion ) &&
             ( "905915" >!< minorversion ) &&
             ( "910620" >!< minorversion ) &&
             ( "912812" >!< minorversion ) &&
             ( "916281" >!< minorversion ) &&
             ( "918899" >!< minorversion ) )

		security_hole(get_kb_item("SMB/transport"));
	else
	    set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB896688", value:TRUE);
}
else
      set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB896688", value:TRUE);
