#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21332);
 script_bugtraq_id (17908);
 script_cve_id("CVE-2006-0027");
 script_version("$Revision: 1.3 $");

 name["english"] = "Vulnerability in Microsoft Exchange Could Allow Remote Code Execution (916803)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the email server.

Description :

The remote host is running a version of exchange which is vulnerable
to a bug in the vCal or iCal attachment handling routine which may 
allow an attacker execute arbitrary code on the remote host by sending
a specially crafted email.

Solution : 

Microsoft has released a set of patches for Exchange 2000 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-019.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Exchange";

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


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

port = get_kb_item ("SMB/transport");

# 2000
if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.0.6618.4") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
# 2003
else if (version == 65)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if (!sp || sp < 1) security_warning(port);
 else if (sp == 2)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"6.5.7650.29") == HCF_OLDER ) security_warning(port);
 }
 else if (sp == 1)
 {
  if ( hotfix_check_fversion(path:rootfile, file:"Cdoex.dll", version:"	6.5.7233.69") == HCF_OLDER ) security_warning(port);
 }
 
 hotfix_check_fversion_end();
}

