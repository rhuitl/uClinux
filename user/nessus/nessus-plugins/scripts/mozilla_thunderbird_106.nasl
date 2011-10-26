#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19269);
 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261");
 script_bugtraq_id(14242);
 script_version("$Revision: 1.6 $");

 name["english"] = "Mozilla Thunderbird < 1.0.6";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla Thunderbird, an email client.

The remote version of this software is vulnerable to several flaws
which may allow an attacker to execute arbitrary commands on the remote host.

Solution : Upgrade to Mozilla ThunderBird 1.0.6
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla Thunderbird";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");

 exit(0);
}


ver = get_kb_item("Mozilla/Thunderbird/Version");
if (!ver) exit(0);

# nb: 1.0.5 is NOT vulnerable but is "buggy" so we should not advise anyone
# to use it (but we don't flag it either)
ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (int(ver[0]) == 1 && int(ver[1]) == 0 && int(ver[2]) < 6)
) security_hole(get_kb_item("SMB/transport"));
