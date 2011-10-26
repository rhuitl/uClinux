#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11145);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0008");
 script_bugtraq_id(5410);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2002-1183","CVE-2002-0862");

 name["english"] = "Certificate Validation Flaw Could Enable Identity Spoofing (Q328145)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to spoof user identity.

Description :

The remote host contains a version of the CryptoAPI which is vulnerable
to a security flaw which may allow an attacker to spoof the identity
of another user with malformed SSL certificates.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-050.mspx

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q328145, Certificate Validation Flaw";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Crypt32.dll", version:"5.131.2600.1123", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Cryptdlg.dll", version:"5.0.1558.6608", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Cryptdlg.dll", version:"5.0.1558.6072", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Crypt32.dll", version:"5.131.1878.12", dir:"\system32") )
   security_note (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329115") > 0  )
	security_note(get_kb_item("SMB/transport"));
 
