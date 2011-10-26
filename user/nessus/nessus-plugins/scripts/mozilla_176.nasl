#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17604);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2005-0399", "CVE-2005-0401");
 script_bugtraq_id(12659, 12798, 12881, 12884, 12885);

 name["english"] = "Mozilla Browser < 1.7.6";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A web browser installed on the remote host contains multiple
vulnerabilities. 

Description :

The remote version of Mozilla contains various security issues which
may allow an attacker to impersonate a website and to trick a user
into accepting and executing arbitrary files or to cause a heap
overflow in the FireFox process and execute arbitrary code on the
remote host. 

Solution : 

Upgrade to Mozilla 1.7.6 or later.

Risk factor : 

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}


ver = get_kb_item("Mozilla/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 7 ||
      (int(ver[1]) == 7 && int(ver[2]) < 6)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
