#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10945);
 script_bugtraq_id(4438);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0051");
 name["english"] = "Opening Group Policy Files (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A user can block access to GPO deployment.

Description :

The remote version of Windows contains a flaw in the Group Policy
Object (GPO) access right of Active Directory which may allow a
user to prevent the GPO to be applied to other users.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-016.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:R/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the Group Policy patch (Q318593) is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q318593") > 0 ) 
	security_note(get_kb_item("SMB/transport"));

