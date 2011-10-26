#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16299);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(8532);
 script_cve_id("CVE-2003-0661");
 name["english"] = "NetBIOS Name Service Reply Information Leakage (824105) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Random portions of memory may be disclosed thru the NetBIOS name service.

Description :

The remote host is running a version of the NetBT name
service which suffers from a memory disclosure problem.

An attacker may send a special packet to the remote NetBT name
service, and the reply will contain random arbitrary data from 
the remote host memory. This arbitrary data may be a fragment from
the web page the remote user is viewing, or something more serious
like a POP password or anything else.

An attacker may use this flaw to continuously 'poll' the content
of the memory of the remote host and might be able to obtain sensitive
information.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP ans 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-034.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS03-034";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Netbt.sys", version:"5.2.3790.69", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Netbt.sys", version:"5.1.2600.1243", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Netbt.sys", version:"5.1.2600.117", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Netbt.sys", version:"5.0.2195.6783", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"4.0", file:"Netbt.sys", version:"4.0.1381.7224", dir:"\system32\drivers") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"824105") > 0 )
	security_hole(get_kb_item("SMB/transport"));
