#
# (C) Tenable Network Security
#
#
# This test is a registry check which complements what mssmtp_code_execution.nasl
# discovers over the network
#
if(description)
{
 script_id(17976);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0013");
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0840");
 name["english"] = "Vulnerability in SMTP Could Allow Remote Code Execution (885881)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host contains a flaw in its SMTP service which could allow remote
code execution.

Vulnerable services are  SMTP service (Windows 2003), Exchange
2003 (Windows 2000) and Exchange 2000.

Solution : 

Microsoft has released a set of patches for Exchange 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-035.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix K885881";

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

if ( hotfix_check_nt_server() <= 0 ) exit(0);

# Superseeded by MS05-021
if ( hotfix_missing(name:"894549") > 0 ) exit(0);

win = get_kb_item ("SMB/WindowsVersion");
version = get_kb_item ("SMB/Exchange/Version");
sp = get_kb_item ("SMB/Exchange/SP");

if ("5.2" >< win)
{
 sp  = get_kb_item("SMB/CSDVersion");
 if ( sp ) exit (0);

 value = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SMTPSVC/DisplayName");
 if (value)
 {
  if (is_accessible_share())
  {
   if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Reapi.dll", version:"6.0.3790.211", dir:"\system32\inetsrv") )
     security_hole (get_kb_item("SMB/transport"));
  }
  else if ( hotfix_missing(name:"885881") > 0 )
     security_hole(get_kb_item("SMB/transport")); 
 }
 exit (0);
}

if (("5.0" >< win) && (version == 65))
{
 if (sp && (sp >= 1)) exit (0);

 if (is_accessible_share())
 {
  path = get_kb_item ("SMB/Exchange/Path") + "\bin";
  if ( hotfix_is_vulnerable (os:"5.0", file:"Reapi.dll", version:"6.5.6980.98", dir:path) )
    security_hole (get_kb_item("SMB/transport"));
  hotfix_check_fversion_end(); 
 }
 else if ( hotfix_missing(name:"885882") > 0 )
   security_hole(get_kb_item("SMB/transport")); 

 exit (0);
}

if (version == 60)
{
 if (sp && (sp >= 4)) exit (0);

 if (is_accessible_share())
 {
  path = get_kb_item ("SMB/Exchange/Path") + "\bin";
  if ( hotfix_is_vulnerable (os:"5.0", file:"Reapi.dll", version:"6.0.6617.25", dir:path) )
    security_hole (get_kb_item("SMB/transport"));
  hotfix_check_fversion_end(); 
 }
 else if ( hotfix_missing(name:"890066") > 0 )
   security_hole(get_kb_item("SMB/transport")); 

 exit (0);
}
