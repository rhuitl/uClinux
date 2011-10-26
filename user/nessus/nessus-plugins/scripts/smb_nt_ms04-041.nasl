#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15966);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(11927, 11929);
 script_cve_id("CVE-2004-0571", "CVE-2004-0901");
 name["english"] = "Vulnerabilities in WordPad (885836)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through WordPad.

Description :

The remote host contains a version of Microsoft WordPad which is vulnerable
to two security flaws.

To exploit these flaws an attacker would need to send a malformed Word file
to a victim on the remote host and wait for him to open the file using WordPad.

Opening the file with WordPad will trigger a buffer overflow which may allow
an attacker to execute arbitrary code on the remote host with the privileges
of the user.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-041.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS04-041";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 path = hotfix_get_programfilesdir() + "\Windows NT\Accessories";

 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wordpad.exe", version:"5.2.3790.224", dir:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wordpad.exe", version:"5.1.2600.1606", dir:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mswrd6.wpc", version:"10.0.803.2", dir:path) ||
      hotfix_is_vulnerable (os:"5.0", file:"Wordpad.exe", version:"5.0.2195.6991", dir:path) || 
      hotfix_is_vulnerable (os:"4.0", file:"Wordpad.exe", version:"4.0.1381.7312", dir:path) )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"885836") > 0 )
	security_hole(get_kb_item("SMB/transport"));
