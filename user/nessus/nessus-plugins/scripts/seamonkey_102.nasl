#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21629);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-2777", "CVE-2006-2781");
  script_bugtraq_id(18228);

  script_name(english:"SeaMonkey < 1.0.2");
  script_summary(english:"Checks version of SeaMonkey");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws. 

Description :

The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges. 

See also :

http://www.mozilla.org/security/announce/2006/mfsa2006-40.html
http://www.mozilla.org/security/announce/2006/mfsa2006-43.html

Solution : 

Upgrade to SeaMonkey 1.0.2 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


ver = get_kb_item("SeaMonkey/Version");
if (!ver) exit(0);
if (
  int(ver[0]) < 1 ||
  (int(ver[0]) == 1 && int(ver[1]) == 0 && int(ver[3]) < 2)
) security_warning(get_kb_item("SMB/transport"));
