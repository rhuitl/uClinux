#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12642);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0648");
 script_bugtraq_id(10681);
 script_xref(name:"OSVDB", value:"7595");

 name["english"] = "Mozilla/Firefox code execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.

The remote version of this software contains a weakness which may allow an
attacker to execute arbitrary programs on the remote host.

Solution : See http://mozilla.org/security/shell.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla/Firefox";

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
      (int(ver[1]) == 7 && int(ver[2]) == 0 && int(ver[3]) < 1)
    )
  )
) 
{
  security_hole(get_kb_item("SMB/transport"));
  exit(0);
}


fox = get_kb_item("Mozilla/Firefox/Version");
if (!fox) exit(0);

ver = split(fox, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
    int(ver[1]) < 9 ||
    (int(ver[1]) == 9 && int(ver[2]) < 2)
  )
) 
{
  security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
