#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22371);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
  script_bugtraq_id(19488, 19534, 20042);

  script_name(english:"SeaMonkey < 1.0.5");
  script_summary(english:"Checks version of SeaMonkey");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws. 

Description :

The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges. 

See also :

http://www.mozilla.org/security/announce/2006/mfsa2006-57.html
http://www.mozilla.org/security/announce/2006/mfsa2006-59.html
http://www.mozilla.org/security/announce/2006/mfsa2006-60.html
http://www.mozilla.org/security/announce/2006/mfsa2006-61.html
http://www.mozilla.org/security/announce/2006/mfsa2006-63.html
http://www.mozilla.org/security/announce/2006/mfsa2006-64.html

Solution : 

Upgrade to SeaMonkey 1.0.5 or later. 

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
  (int(ver[0]) == 1 && int(ver[1]) == 0 && int(ver[3]) < 5)
) security_warning(get_kb_item("SMB/transport"));
