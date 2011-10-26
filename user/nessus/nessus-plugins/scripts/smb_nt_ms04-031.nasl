#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15456);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0035");
 script_bugtraq_id(11372);
 script_cve_id("CVE-2004-0206");

 script_version("$Revision: 1.9 $");
 name["english"] = "Vulnerability in NetDDE Could Allow Code Execution (841533)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through NetDDE service.

Description :

The remote version of Windows is affected by a vulnerability in 
Network Dynamic Data Exchange (NetDDE).

To exploit this flaw, NetDDE would have to be running and an attacker
with a specific knowledge of the vulnerability would need to send a malformed
NetDDE message to the remote host to overrun a given buffer.

A public exploit is available to exploit this vulnerability.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms04-031.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 841533 has been installed";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Netdde.exe", version:"5.2.3790.184", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Netdde.exe", version:"5.1.2600.1567", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Netdde.exe", version:"5.1.2600.158", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Netdde.exe", version:"5.0.2195.6952", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Netdde.exe", version:"4.0.1381.7280", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"841533") > 0  )
	security_hole(get_kb_item("SMB/transport"));

