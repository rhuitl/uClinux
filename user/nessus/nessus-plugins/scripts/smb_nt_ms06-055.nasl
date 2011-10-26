#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22449);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2006-4868");
 script_bugtraq_id(20096);

 name["english"] = "Vulnerability in Vector Markup Language Could Allow Remote Code Execution (925486)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the email client or
the web browser.

Description :

The remote host is running a version of Internet Explorer or Outlook Express 
which is vulnerable to a bug in the Vector Markup Language (VML) handling routine 
which may allow an attacker execute arbitrary code on the remote host by sending
a specially crafted email or by luring a user on the remote host into visiting
a rogue web site.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-055.mspx

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 925486";

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



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

dir = hotfix_get_commonfilesdir();
if (isnull(dir))
  exit (0);


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Vgx.dll", version:"6.0.3790.593", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Vgx.dll", version:"6.0.3790.2794", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Vgx.dll", version:"6.0.2800.1580", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Vgx.dll", version:"6.0.2900.2997", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.0", file:"Vgx.dll", version:"6.0.2800.1580", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:dir) ||
      hotfix_is_vulnerable (os:"5.0", file:"Vgx.dll", version:"5.0.3845.1800", dir:"\Microsoft Shared\VGX", path:dir) )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
if ( hotfix_missing(name:"925486") > 0 )
	{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( "925486" >!< minorversion ) security_warning(get_kb_item("SMB/transport"));
	}

}
