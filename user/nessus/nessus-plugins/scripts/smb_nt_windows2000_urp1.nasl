#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18592);
 script_bugtraq_id(14093);
 script_version ("$Revision: 1.4 $");
 
 name["english"] =  "Microsoft Update Rollup 1 for Windows 2000 SP4 missing";
 
 script_name(english:name["english"]);
 	     
 
 desc["english"] = "
Synopsis :

A security update is missing on the remote host.

Description :

The remote host is missing the Update Rollup 1 (URP1) for Windows 2000 SP4.

This update rollup contains several security fixes in addition to previously
released security patches.

Solution :

http://support.microsoft.com/kb/891861/

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 		    
 
 summary["english"] = "Determines whether the URP1 is installed";
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

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);

if (is_accessible_share ())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"eventlog.dll", version:"5.0.2195.7036", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"Update Rollup 1") > 0 ) 
   security_warning(get_kb_item("SMB/transport"));
