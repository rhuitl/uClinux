#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Marcel Boesch <marboesc@student.ethz.ch>.
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14668);
 script_bugtraq_id(10703);
 script_cve_id("CVE-2004-0758");
 script_version("$Revision: 1.7 $");

 name["english"] = "Mozilla/Firefox security manager certificate handling DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla, an alternative web browser.

The Mozilla Personal Security Manager (PSM) contains  a flaw
that may permit a attacker to import silently a certificate into
the PSM certificate store.
This corruption may result in a deny of SSL connections.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla/Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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
      (int(ver[1]) == 7 && int(ver[2]) < 1)
    )
  )
) 
{
  security_warning(get_kb_item("SMB/transport"));
  exit(0);
}


fox = get_kb_item("Mozilla/Firefox/Version");
if (!fox) exit(0);

ver = split(fox, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
    int(ver[1]) < 9 ||
    (int(ver[1]) == 9 && int(ver[2]) < 3)
  )
) 
{
  security_warning(get_kb_item("SMB/transport"));
  exit(0);
}
