#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21322);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1993");
  script_bugtraq_id(17671);

  script_name(english:"Firefox < 1.5.0.3");
  script_summary(english:"Checks Firefox version number");

  desc = "
Synopsis :

A web browser on the remote host may be prone to a denial of service
attack. 

Description :

The installed version of Firefox may allow a malicious site to crash
the browser and potentially to run malicious code when attempting to
use a deleted controller context. 

Successful exploitation requires that 'designMode' be turned on. 

See also : 

http://www.securityfocus.com/archive/1/archive/1/431878/100/0/threaded
http://www.mozilla.org/security/announce/2006/mfsa2006-30.html

Solution : 

Upgrade to Firefox 1.5.0.3 or later. 

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


ver = get_kb_item("Mozilla/Firefox/Version");

if (!ver) exit(0);
ver = split(ver, sep:'.', keep:FALSE);
if (int(ver[0]) == 1 && int(ver[1]) == 5 && int(ver[2]) == 0 && int(ver[3]) < 3) 
  security_warning(get_kb_item("SMB/transport"));
