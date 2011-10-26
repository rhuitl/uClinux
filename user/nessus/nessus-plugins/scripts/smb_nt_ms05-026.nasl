#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18482);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(13953);
 script_cve_id("CVE-2005-1208");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0017");

 
 script_version("$Revision: 1.7 $");
 name["english"] = "Vulnerability in HTML Help Could Allow Remote Code Execution (896358)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains a version of the HTML Help ActiveX control which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and entice a victim to visit this web page.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-026.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896358";

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Hhctrl.ocx", version:"5.2.3790.315", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.2427", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.315", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Hhctrl.ocx", version:"5.2.3790.2453", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3790.309", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"896358") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


