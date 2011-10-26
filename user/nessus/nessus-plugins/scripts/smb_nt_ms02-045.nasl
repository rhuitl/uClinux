#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11300);
 script_bugtraq_id(5556);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0724");
 
 name["english"] = "Unchecked buffer in Network Share Provider (Q326830)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host.

Description :

The remote host is vulnerable to a denial of service attack,
which could allow an attacker to crash it by sending a specially
crafted SMB (Server Message Block) request to it.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-045.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q326830";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Xartsrv.dll", version:"5.1.2600.50", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Xartsrv.dll", version:"5.0.2195.5971", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xartsrv.dll", version:"4.0.1381.7181", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xartsrv.dll", version:"4.0.1381.33538", min_version:"4.0.1381.33000", dir:"\system32") )
   security_note (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q326830") > 0 )  
	security_note(get_kb_item("SMB/transport"));

