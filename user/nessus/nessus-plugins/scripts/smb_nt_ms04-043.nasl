#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15964);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(11916);
 script_cve_id("CVE-2004-0568");
 name["english"] = "Vulnerabilities in HyperTerminal (873339)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through HyperTerminal.

Description :

The remote host contains a version of the HyperTerminal software which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by tricking a victim into using Hyperterminal
to log into a rogue host.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-043.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-043";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Hypertrm.dll", version:"5.2.3790.233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Hypertrm.dll", version:"5.1.2600.1609", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Hypertrm.dll", version:"5.1.2600.2563", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hypertrm.dll", version:"5.0.2195.7000", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Hypertrm.dll", version:"4.0.1381.7323", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}

