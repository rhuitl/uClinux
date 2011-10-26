#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17218);
 if ( NASL_LEVEL >= 2191 ) script_bugtraq_id(12533, 12461, 12470, 12468, 12466, 12465, 12234, 12153, 11854, 11823, 11752, 12655, 12728);
 script_cve_id("CVE-2005-0230", "CVE-2005-0591");
 script_version("$Revision: 1.9 $");

 name["english"] = "Firefox < 1.0.1";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains various security issues which may
allow an attacker to impersonate a website by using an International Domain Name
(IDN) or to trick a user into accepting and executing arbitrary files.

Solution : Upgrade to Firefox 1.0.1 or later.
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
  if (ereg(pattern:"^(0\.[0-9]\.|1\.0\.0)", string:fox) )
     security_hole(0);
}
