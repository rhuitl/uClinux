#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11790);
 script_bugtraq_id(8205, 8458, 8460);
 script_version("$Revision: 1.26 $");
 script_cve_id("CVE-2003-0352", "CVE-2003-0715", "CVE-2003-0528", "CVE-2003-0605");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0011");
 
 name["english"] = "Buffer overrun in RPC Interface (824146)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of Windows which has a flaw in 
its RPC interface, which may allow an attacker to execute arbitrary code 
and gain SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-026.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q824146";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

if ( get_kb_item("SMB/KB824146") ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rpcrt4.dll", version:"5.2.3790.59", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rpcrt4.dll", version:"5.1.2600.1230", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rpcrt4.dll", version:"5.1.2600.109", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.6753", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.7219", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.33474", min_version:"4.0.1381.33000", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"824146") > 0 && 
          hotfix_missing(name:"828741") > 0 &&
          hotfix_missing(name:"873333") > 0 &&
          hotfix_missing(name:"902400") > 0 &&
	  !((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 ) ) )
	security_hole(get_kb_item("SMB/transport"));
