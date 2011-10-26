#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15455);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0033");
 script_bugtraq_id(11384);
 script_cve_id("CVE-2003-0718");

 script_version("$Revision: 1.8 $");
 name["english"] = "WebDAV XML Message Handler Denial of Service (824151)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote web server.

Description :

The remote host is running a version of Windows and IIS which is vulnerable
to a remote denial of service attack through the WebDAV XML Message Handler.

An attacker may exploit this flaw to prevent the remote web server from
working properly.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms04-030.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 824151 has been installed";

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

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msxml3.dll", version:"8.50.2162.0", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"824151") > 0  )
	security_warning(get_kb_item("SMB/transport"));

