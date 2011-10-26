#
# (C) Tenable Network Security
#


if (description) {
  script_id(19718);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2602");
  script_bugtraq_id(14526, 14916, 14917, 14918, 14919, 14920, 14921, 14923, 14924);

  name["english"] = "Mozilla Browser < 1.7.12";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

A web browser on the remote host is prone to multiple flaws, including
arbitrary code execution. 

Description :

The installed version of Mozilla contains various security issues,
several of which are critical as they can be easily exploited to
execute arbitrary shell code on the remote host. 

See also : 

http://security-protocols.com/advisory/sp-x17-advisory.txt
http://www.mozilla.org/security/idn.html
http://www.mozilla.org/security/announce/2005/mfsa2005-58.html

Solution : 

Upgrade to Mozilla 1.7.12 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Mozilla browser < 1.7.12";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
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
      (int(ver[1]) == 7 && int(ver[2]) < 12)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
