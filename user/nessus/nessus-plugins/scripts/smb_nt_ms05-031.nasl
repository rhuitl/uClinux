#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18492);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(13944);
 script_cve_id("CVE-2005-1212");
 name["english"] = "Vulnerability in Step-by-Step Interactive Training (898458)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the training
software.

Description :

The remote host is running a version of Microsoft Step-by-Step Interactive 
Training which contains a flaw which may lead to remote code execution.

To exploit this flaw, an attacker would need to trick a user on the remote host
into opening a malformed file with the affected application.

Solution : 

Microsoft has released a patch :

http://www.microsoft.com/technet/security/bulletin/ms05-031.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MRUN32.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

if ( hotfix_check_fversion(file:"mrun32.exe", version:"3.4.1.101") == HCF_OLDER ) security_hole(kb_smb_transport());

hotfix_check_fversion_end();
