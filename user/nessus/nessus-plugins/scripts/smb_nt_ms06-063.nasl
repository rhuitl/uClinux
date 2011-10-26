#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22536);
 script_bugtraq_id(20373);
 script_version("$Revision: 1.2 $");
 script_cve_id("CVE-2006-1314", "CVE-2006-1315");

 name["english"] = "Vulnerability in Server Service Could Allow Denial of Service (923414)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host due to a flaw in the 'server' service.

Description :

The remote host is vulnerable to memory corruption vulnerability in the 'Server'
service which may allow an attacker to perform a denial of service against the
remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-063.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 923414";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Srv.sys", version:"5.2.3790.588", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.2783", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1885", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.2974", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7106", dir:"\system32\drivers") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"923414") > 0 )
  security_warning(get_kb_item("SMB/transport"));


