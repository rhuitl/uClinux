#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17603);
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-4809");
 script_bugtraq_id(12659, 12672, 12798, 12881, 12884, 12885);

 name["english"] = "Firefox < 1.0.2";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains various security issues which may
allow an attacker to impersonate a website and to trick a user into 
accepting and executing arbitrary files or to cause a heap overflow in the
FireFox process and execute arbitrary code on the remote host.

Solution : Upgrade to Firefox 1.0.2 or later.
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
  if (ereg(pattern:"^(0\.[0-9]\.|1\.0\.[01]([^0-9]|$))", string:fox) )
     security_hole(0);
}
