#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19998);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0042");
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2307");

 name["english"] = "Vulnerability in Network Connection Manager Could Allow Denial of Service (905414)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A flaw in the remote network connection manager may allow an attacker to cause
a denial of service on the remote host.

Description :

The remote host contains a version of the Network Connection Manager which
contains a denial of service vulnerability which may allow an attacker to
disable the component responsible for managing network and remote access
connections.

To exploit this vulnerability, an attacker would need to send a malformed
packet to the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-045.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 905414";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"netman.dll", version:"5.2.3790.396", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"netman.dll", version:"5.2.3790.2516", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"netman.dll", version:"5.1.2600.1733", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"netman.dll", version:"5.1.2600.2743", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"netman.dll", version:"5.0.2195.7061", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"905414") > 0 ) security_warning(get_kb_item("SMB/transport"));
