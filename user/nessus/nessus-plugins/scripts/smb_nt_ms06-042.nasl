#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22184);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2006-3280", "CVE-2006-3450", "CVE-2006-3451", "CVE-2006-3637", "CVE-2006-3638", "CVE-2006-3639", "CVE-2006-3640", "CVE-2004-1166");
 script_bugtraq_id(19312, 19316, 19340, 19339, 19400, 19987);

 name["english"] = "Cumulative Security Update for Internet Explorer (918899)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host is missing the IE cumulative security update 918899.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host.

Note that Microsoft has re-released this hotfix as its initial version
contained a buffer overflow. 


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-042.mspx

See also :

http://support.microsoft.com/kb/923762/

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 918899";

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


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Urlmon.dll", version:"6.0.3790.566", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2759", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Urlmon.dll", version:"6.0.2800.1572", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2963", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Urlmon.dll", version:"6.0.2800.1572", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Urlmon.dll", version:"5.0.3844.3000", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
if ( hotfix_missing(name:"918899") > 0 )
	{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( "918899" >!< minorversion ) security_warning(get_kb_item("SMB/transport"));
	}

}
