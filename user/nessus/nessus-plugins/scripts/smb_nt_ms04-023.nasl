#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13641);
 script_bugtraq_id(10705, 9320);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0201", "CVE-2003-1041");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0012");
 name["english"] = "Vulnerability in HTML Help Could Allow Code Execution (840315)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host is subject to two vulnerabilities in the HTML Help and showHelp
modules, which could allow an attacker to execute arbitrary code on the remote 
host.

To exploit this flaw, an attacker would need to set up a rogue website
containing a malicious showHelp URL, and would need to lure a user on the
remote host to visit it. Once the user visits the web site, a buffer overflow
would allow the attacker to execute arbitrary commands with the privileges
of the victim user.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-023.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-023 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:1, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Itss.dll", version:"5.2.3790.185", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"840315") > 0 && hotfix_missing(name:"896358") > 0  )
	security_hole(get_kb_item("SMB/transport"));

