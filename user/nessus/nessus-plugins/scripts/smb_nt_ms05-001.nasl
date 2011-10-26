#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16123);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-1043");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0002");

 name["english"] = "HTML Help Code Execution (890175) (registry check)";
 
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

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-001.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS05-001";

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

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Hhctrl.ocx", version:"5.2.3790.1280", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Hhctrl.ocx", version:"5.2.3790.233", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"890175") > 0 && 
      hotfix_missing(name:"922616") > 0 &&
      hotfix_missing(name:"896358") > 0 )
   security_hole(get_kb_item("SMB/transport"));
}
