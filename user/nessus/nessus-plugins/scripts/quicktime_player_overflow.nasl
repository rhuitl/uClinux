#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11506);
 script_bugtraq_id(7247);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0168");
 
 
 name["english"] = "Quicktime player buffer overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of the Quicktime player is vulnerable to
a buffer overflow.

To exploit it, an attacker would need a user of this host to
visit a rogue webpage with a malformed link in it. He could
then be able to execute arbitrary code with the rights of the user
visiting the page.
	

Solution : Upgrade to Quicktime Player version 6.1 or later.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Quicktime Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");

 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-5]\.|6\.0\.)") security_hole(get_kb_item("SMB/transport"));
