#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18689);
 script_version("$Revision: 1.5 $");

 script_bugtraq_id(14242, 14325);
 name["english"] = "Firefox < 1.0.6";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains various security issues which may
allow an attacker to execute arbitrary code on the remote host.

Solution : Upgrade to Firefox 1.0.6.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}




fox = get_kb_item("Mozilla/Firefox/Version");
if (fox)
{
  if (ereg(pattern:"^(0\.[0-9]\.|1\.0\.[0-5]([^0-9]|$))", string:fox) )
     security_hole(0);
}
