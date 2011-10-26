#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11307);
 script_bugtraq_id(4248);
 script_version("$Revision: 1.9 $");
 
 script_cve_id("CVE-2002-0070");
 
 name["english"] = "Unchecked buffer in Windows Shell";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The Windows shell of the remote host has an unchecked buffer
which can be exploited by a local attacker to run arbitrary code 
on this host. 

Solution : 

Microsoft has released a set of patches for Windows NT and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-014.mspx

Risk factor : 

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q216840";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) > 0 )
{
 if ( hotfix_missing(name:"839645") == 0 ) exit(0);
}

if ( hotfix_missing(name:"313829") > 0 && hotfix_missing(name:"841356") > 0 )
	security_hole(get_kb_item("SMB/transport"));

