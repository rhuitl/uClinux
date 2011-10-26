#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15962);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0016");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0039");
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(11763, 11922);
 script_cve_id("CVE-2004-0567", "CVE-2004-1080");
 name["english"] = "WINS Code Execution (870763) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to WINS service.

Description :

The remote Windows Internet Naming Service (WINS) is vulnerable to a Heap
overflow vulnerability which could allow an attacker to execute arbitrary
code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
packet on port 42 of the remote host.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-045.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-045";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_check_wins_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wins.exe", version:"5.2.3790.239", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Wins.exe", version:"5.0.2195.7005", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Wins.exe", version:"4.0.1381.7329", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"870763") > 0 )
	security_hole(get_kb_item("SMB/transport"));
