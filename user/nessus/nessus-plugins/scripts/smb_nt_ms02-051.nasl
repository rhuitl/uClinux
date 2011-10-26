#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11146);
 script_bugtraq_id(5410, 5711, 5712);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0863");

 name["english"] = "Cryptographic Flaw in RDP Protocol can Lead to Information Disclosure (Q324380)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote desktop service.

Description :

The remote host contains a version of the Remote Desktop protocol/service
which is vulnerable to a security flaw which may allow an attacker to crash
the remote service and cause the system to stop responding.
Another vulnerability may allow an attacker to disclose information.

Solution : 

Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-051.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q324380, Flaws in Microsoft RDP";

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

if ( hotfix_check_sp(xp:1, win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rdpwd.sys", version:"5.1.2600.48", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rdpwd.sys", version:"5.0.2195.5880", dir:"\system32\drivers") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q324380") > 0 )
	security_hole(get_kb_item("SMB/transport"));

