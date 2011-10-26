#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18024);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0560");
 script_bugtraq_id(13118);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0010");

 name["english"] = "Vulnerability in SMTP Could Allow Remote Code Execution (894549)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the SMTP server.

Description :

The remote host contains a flaw in its SMTP service which could allow remote
code execution.
Vulnerable services are  Exchange 2003 (Windows 2000) and Exchange 2000.

A public code is available to exploit this vulnerability.

Solution : 

Microsoft has released a set of patches for Exchange 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-021.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 894549";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_nt_server() <= 0 ) exit(0);

version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");


if ( ! version ) exit(0);

if ( version == 65 )
{
 if (sp && (sp >= 2)) exit (0);

 if (is_accessible_share())
 {
  if (sp)
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.7232.89", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) security_warning(port);
  }
  else
  {
   if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.5.6981.3", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) security_warning(port);
  }
  hotfix_check_fversion_end(); 
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
    security_hole(get_kb_item("SMB/transport")); 
 }
 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if (is_accessible_share())
 {
  if ( hotfix_check_fversion(file:"Xlsasink.dll", version:"6.0.6617.52", path:get_kb_item("SMB/Exchange/Path") + "\bin") == HCF_OLDER ) security_hole(port);
  hotfix_check_fversion_end(); 
 }
 else
 {
  if ( hotfix_missing(name:"894549") > 0 )
    security_hole(get_kb_item("SMB/transport")); 
 }
 exit (0);
}
