#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18215);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0016");
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(13248);
 script_cve_id("CVE-2005-1191");

 
 script_version("$Revision: 1.8 $");
 name["english"] = "Vulnerability in Web View Could Allow Code Execution (894320)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Explorer.

Description :

The remote host is running a version of Microsoft Windows which contains a 
security flaw in the Web View of the Windows Explorer which may allow an 
attacker to execute arbitrary code on the remote host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have it preview it using the Web View with the Windows 
Explorer.

Solution : 

Microsoft has released a patch for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms05-024.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of KB894320";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Webvw.dll", version:"5.0.3900.7036", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"894320") > 0 &&
          hotfix_missing(name:"900725") > 0  )
    security_hole(get_kb_item("SMB/transport"));
