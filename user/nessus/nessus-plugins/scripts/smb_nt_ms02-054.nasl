#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11148);
 script_bugtraq_id(5873, 5876);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0370", "CVE-2002-1139"); 

 name["english"] = "Unchecked Buffer in File Decompression Functions Could Lead to Code Execution (Q329048)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Explorer.

Description :

The remote host contains a version of Windows which is vulnerable to a 
security flaw in the compressed files (ZIP) implementation.
An attacker can exploit this flaw by sending a malicious zip files
to the remote user. When the user opens the file with explorer
the code will be executed.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-054.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329048, Unchecked Buffer in Decompression functions";

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


if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Zipfldr.dll", version:"6.0.2600.1126", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Zipfldr.dll", version:"6.0.2600.101", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"329048") > 0 &&
          hotfix_missing(name:"873376") > 0 )
    security_warning(get_kb_item("SMB/transport"));

