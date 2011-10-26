#
# (C) Tenable Network Security
#
#
#

if(description)
{
 script_id(11802);
 script_bugtraq_id(8259);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2003-0525");
 
 name["english"] = "Flaw in Windows Function may allow DoS (823803)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host.

Description :

The remote host is running a version of Windows NT 4.0 which has a flaw in 
one of its function which may allow a user to cause a denial
of service on this host.

Solution : 

Microsoft has released a set of patches for Windows NT :

http://www.microsoft.com/technet/security/bulletin/ms03-029.mspx

Risk factor :

Low / CVSS Base Score : 3 
(AV:L/AC:H/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 823803";

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

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"Kernel32.dll", version:"4.0.1381.7224", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Kernel32.dll", version:"4.0.1381.33549", min_version:"4.0.1381.33000", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q823803") > 0 ) 
	security_note(get_kb_item("SMB/transport"));
