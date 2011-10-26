#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20001);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0040");
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2005-1987");
 script_bugtraq_id(15067);

 name["english"] = "Vulnerability in the Microsoft Collaboration Data Objects Could Allow Remote Code Execution (907245)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A flaw in the Microsoft Collaboration Data Object may allow an attacker
to execute arbitrary code on the remote host.

Description :

An unchecked buffer condition may allow an attacker to execute arbitrary
code on the remote host.

To execute this flaw, an attacker would need to send a malformed message
via SMTP to the remote host, either by using the SMTP server
(if Exchange is installed) or by sending an email to a user on the remote
host.

When the email is processed by CDO, an unchecked buffer may allow cause
code execution.


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-048.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 907245";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"cdosys.dll", version:"6.5.6749.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"cdosys.dll", version:"6.5.6756.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"cdosys.dll", version:"6.1.1002.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"cdosys.dll", version:"6.1.3940.42", dir:"\system32") )
      {
      security_hole(get_kb_item("SMB/transport"));
      exit(0);
      }

 version = get_kb_item ("SMB/Exchange/Version");
 if (version == 60)
 {
  sp = get_kb_item ("SMB/Exchange/SP");
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile || ( sp && sp >= 4) ) exit(0);
  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"cdoex.dll", version:"6.0.6617.86") == HCF_OLDER ) security_hole(port);

  hotfix_check_fversion_end();
 }
  exit (0);
}
else if ( hotfix_missing(name:"901017") > 0 ) security_hole(get_kb_item("SMB/transport"));
