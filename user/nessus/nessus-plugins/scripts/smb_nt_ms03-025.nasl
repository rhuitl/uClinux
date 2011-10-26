#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11789);
 script_bugtraq_id(8154, 8205);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0350");
 
 name["english"] = "Flaw in message handling through utility mgr";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The remote host runs a version of windows which has a flaw in the way
the utility manager handles Windows messages. As a result, it is possible
for a local user to gain additional privileges on this host.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-025.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q822679";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

if ( hotfix_check_sp(win2k:4) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Umandlg.dll", version:"1.0.0.3", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"822679") > 0 && hotfix_missing(name:"842526") > 0 )
	security_hole(get_kb_item("SMB/transport"));
