#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21693);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-2380");
 script_bugtraq_id(18389);

 name["english"] = "Vulnerability in RPC Mutual Authentication Could Allow Spoofing (917736)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to spoof an RPC server.

Description :

The remote version of Windows contains a version of SMB (Server
Message Block) protocol which is vulnerable to a spoofing attack.

An attacker may exploit these flaws to enduce a user to connect to
a malicious RPC server.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-031.mspx

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 917736";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
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


if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0",       file:"Rpcrt4.dll", version:"5.0.2195.7085", dir:"\system32") )
      security_note(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"917736") > 0 ) security_note(get_kb_item("SMB/transport"));
