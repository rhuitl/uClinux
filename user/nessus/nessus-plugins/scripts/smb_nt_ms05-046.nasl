#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19999);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(15066);
 script_cve_id("CVE-2005-1985");

 name["english"] = "Vulnerability in the Client Service for NetWare Could Allow Remote Code Execution (899589)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A flaw in the client service for NetWare may allow an attacker to execute
arbitrary code on the remote host.

Description :

The remote host contains a version of the Client Service for NetWare which 
is vulnerable to a buffer overflow.

An attacker may exploit this flaw by connecting to the NetWare RPC service
(possibly over IP) and trigger the overflow by sending a malformed RPC
request.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-046.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 899589";

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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"nwwks.dll", version:"5.2.3790.386", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"nwwks.dll", version:"5.2.3790.2506", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"nwwks.dll", version:"5.1.2600.1727", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"nwwks.dll", version:"5.1.2600.2736", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"nwwks.dll", version:"5.0.2195.7065", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"899589") > 0 ) security_hole(get_kb_item("SMB/transport"));
