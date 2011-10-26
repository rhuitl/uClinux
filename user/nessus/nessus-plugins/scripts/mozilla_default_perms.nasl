#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Max <spamhole@gmx.at>
#
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15432);
 script_bugtraq_id(11166);
 script_cve_id("CVE-2004-0906");
 script_version("$Revision: 1.7 $");

 name["english"] = "Mozilla/Firefox default installation file permission flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.

The remote version of this software is prone to an improper file permission
setting.

This flaw only exists if the browser is installed by the Mozilla Foundation
package management, thus this alert might be a false positive.

A local attacker could overwrite arbitrary files or execute arbitrary code in
the context of the user running the browser.

Solution : Update to the latest version of the software
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
      (int(ver[1]) == 7 && int(ver[2]) < 3)
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
if (int(ver[0])) 
{
  security_warning(get_kb_item("SMB/transport"));
  exit(0);
}
