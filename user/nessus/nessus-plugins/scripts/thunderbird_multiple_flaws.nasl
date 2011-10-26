#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14729);
 script_cve_id("CVE-2004-0903", "CVE-2004-0904");
 script_bugtraq_id(11174, 11171, 11170);
 script_version("$Revision: 1.8 $");

 name["english"] = "Mozilla/Thunderbird multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Thunderbird, an alternative mail user
agent.

The remote version of this software is vulnerable to several flaws which
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a rogue email
to a victim on the remote host.

Solution : Upgrade to Mozilla 1.7.3 or ThunderBird 0.8 or later.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");

 exit(0);
}




moz = get_kb_item("Mozilla/Version");
if (!moz) exit(0);

ver = split(moz, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 7 ||
      (int(ver[1]) == 7 && int(ver[2]) < 3)
    )
  )
) 
{
  security_hole(get_kb_item("SMB/transport"));
  exit(0);
}


bird = get_kb_item("Mozilla/Thunderbird/Version");
if (!bird) exit(0);

ver = split(bird, sep:'.', keep:FALSE);
if (int(ver[0]) == 0 && int(ver[1]) < 8) 
{
  security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
