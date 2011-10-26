#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10865);
 script_version("$Revision: 1.19 $");

 # "CVE-2002-0012" and "CVE-2002-0013" too?
 script_cve_id("CVE-2002-0053");
 script_bugtraq_id(4089);

 name["english"] = "Unchecked Buffer in SNMP Service Could Enable Arbitrary Code to be Run";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host. 

Description :

A buffer overrun is present in the SNMP service on the remote host. 
By sending a malformed management request, an attacker could cause a
denial of service and possibly cause code to run on the system in the
LocalSystem context. 

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-006.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of hotfix Q314147";

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


include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, xp:1, win2k:3) <= 0 ) exit(0);

if ( hotfix_missing(name:"314147") > 0  )
  security_hole(port);
