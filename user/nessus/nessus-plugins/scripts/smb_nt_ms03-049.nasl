# 
# (C) Tenable Network Security
#

if(description)
{
 script_id(11921);
 script_bugtraq_id(9011);
 script_version("$Revision: 1.22 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0008");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0018");
 script_cve_id("CVE-2003-0812");
 if( defined_func("script_xref") ) script_xref(name:"CERT", value:"CA-2003-28");
 
 name["english"] = "Buffer Overflow in the Workstation Service (828749)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a flaw in the function 
NetpValidateName() in the WorkStation service which may allow an 
attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

A series of worms (Welchia, Spybot, ...) are known to exploit this
vulnerability in the wild.

Solution : 

Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-049.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 828749";

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

if (hotfix_check_sp(xp:2) > 0 )
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msasn1.dll", version:"5.1.2600.1309", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msasn1.dll", version:"5.1.2600.121", dir:"\system32") )
    security_hole (get_kb_item("SMB/transport"));
 
  hotfix_check_fversion_end();
  exit (0);
 }
 else if ( hotfix_missing(name:"KB828035") > 0) 
	security_hole(get_kb_item("SMB/transport"));
}

if ( hotfix_check_sp(win2k:5) > 0 )
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.0", file:"wkssvc.dll", version:"5.0.2195.6862", dir:"\system32") )
    security_hole (get_kb_item("SMB/transport"));

  hotfix_check_fversion_end();
  exit (0);
 }
 else if ( hotfix_missing(name:"KB828749") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
}
