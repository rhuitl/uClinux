#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15996);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12057);
 name["english"] = "Windows XP SP2 Firewall Critical Update (886185)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Microsoft Windows XP SP2 lacks the critical security
update 886185.

This update fixes a flaw which renders the SP2 firewall ineffective when
the user connects to the internet using a dialup connection.

Solution : http://support.microsoft.com/kb/886185
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for KB886185";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");


# Only XP SP2 affected
if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);
if ( hotfix_check_sp(xp:2) > 0  ) exit(0);

if ( hotfix_missing(name:"886185") > 0 )
	security_hole(get_kb_item("SMB/transport"));
