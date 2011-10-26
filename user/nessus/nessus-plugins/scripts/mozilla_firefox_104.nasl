#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18243);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-T-0014");
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-1476", "CVE-2005-1477");
 script_bugtraq_id(13544, 13641, 13645);

 name["english"] = "Firefox < 1.0.4";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains various security issues which may
allow an attacker to execute arbitrary code on the remote host

Solution : Upgrade to Firefox 1.0.4 or later.
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
  if (ereg(pattern:"^(0\.[0-9]\.|1\.0\.[0-3]([^0-9]|$))", string:fox) )
     security_hole(0);
}
