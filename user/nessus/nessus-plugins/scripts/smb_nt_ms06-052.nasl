#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22332);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(19922);
 script_cve_id("CVE-2006-3442");

 name["english"] = "Vulnerability in Pragmatic General Multicast (PGM) Could Allow Remote Code Execution (919007)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows is affected by a vulnerability in the
Pragmatic General Multicast protocol installed with the MSMQ service.

An attacker may exploit this flaw to execute arbitrary code on the remote
host with KERNEL privileges.

Solution : 

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms06-052.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 919007 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rmcast.sys", version:"5.1.2600.1873", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rmcast.sys", version:"5.1.2600.2951", dir:"\system32\drivers") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"919007") > 0  )
  security_warning(get_kb_item("SMB/transport"));
