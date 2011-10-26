#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21247);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-0015");
  script_bugtraq_id(17452);

  script_name(english:"FrontPage fpadmdll.dll Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Checks version of FrontPage's fpadmdll.dll");

  desc = "
Synopsis :

The remote web server contains a server extension that is affected by
several cross-site scripting flaws. 

Description :

The version of Microsoft FrontPage Server Extensions 2002 / SharePoint
Team Services on the remote host fails to sanitize user-supplied input
to the 'operation', 'command', and 'name' parameters of
'/_vti_bin/_vti_adm/fpadmdll.dll' before using it to generate dynamic
HTML.  An attacker may be able to exploit this issue to cause
arbitrary HTML and script code to be executed by a user's browser in
the context of the affected web site.  If the user is an
administrator, successful exploitation will give the attacker complete
control over the affected application. 

Solution :

Microsoft has released a set of patches for Frontapage 2002 for XP and
2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-017.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if (hotfix_check_sp(xp:3, win2003:2) <= 0) exit(0);
fp_root = get_kb_item ("Frontpage/2002/path");
if (!fp_root) exit (0);

if (is_accessible_share())
{
  if (hotfix_check_fversion(file:"fpadmdll.dll", path:fp_root + "\isapi\_vti_adm", version:"10.0.6790.0") == HCF_OLDER)
    security_warning(get_kb_item("SMB/transport"));
  hotfix_check_fversion_end();
}
else if (
  hotfix_missing(name:"908981") > 0 && 
  hotfix_missing(name:"911831") > 0 && 
  hotfix_missing(name:"911701") > 0
) security_warning(get_kb_item("SMB/transport"));
