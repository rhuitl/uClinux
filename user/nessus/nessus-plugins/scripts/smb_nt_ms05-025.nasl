#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18490);
 script_version("$Revision: 1.17 $");
 script_bugtraq_id(5560, 13947, 13946, 13943, 13941);
 script_cve_id("CVE-2005-1211", "CVE-2002-0648");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0016");

 
 script_version("$Revision: 1.17 $");
 name["english"] = "Cumulative Security Update for Internet Explorer (883939)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host is missing the IE cumulative security update 883939.

The remote version of IE is vulnerable to several flaws which may allow an attacker to
execute arbitrary code on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-025.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 883939";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl","smb_nt_ms05-038.nasl");
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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.327", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2440", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1505", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2668", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1505", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Mshtml.dll", version:"5.0.3541.2700", dir:"\system32") || 
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Mshtml.dll", version:"5.0.3828.2700", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:5, file:"Mshtml.dll", version:"5.0.3828.2700", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
if ( hotfix_missing(name:"896727") <= 0 ) exit(0); 
if ( hotfix_missing(name:"896688") <= 0 ) exit(0); 
if ( hotfix_missing(name:"905915") <= 0 ) exit(0); 
if ( hotfix_missing(name:"910620") <= 0 ) exit(0);
if ( hotfix_missing(name:"912812") <= 0 ) exit(0);
if ( hotfix_missing(name:"916281") <= 0 ) exit(0);
if ( hotfix_missing(name:"918899") <= 0 ) exit(0); 
if ( hotfix_missing(name:"883939") > 0 )
	{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( ( "883939" >!< minorversion ) &&
             ( "896688" >!< minorversion ) &&
             ( "905915" >!< minorversion ) &&
             ( "910620" >!< minorversion ) &&
             ( "912812" >!< minorversion ) &&
             ( "916281" >!< minorversion ) &&
             ( "918899" >!< minorversion ) &&
             ( "883939" >!< minorversion ) )
	 security_hole(get_kb_item("SMB/transport"));
	}

}
