#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21556);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2006-1249",
    "CVE-2006-1453", 
    "CVE-2006-1454", 
    "CVE-2006-1458", 
    "CVE-2006-1459", 
    "CVE-2006-1460", 
    "CVE-2006-1461", 
    "CVE-2006-1462", 
    "CVE-2006-1463", 
    "CVE-2006-1464", 
    "CVE-2006-1465", 
    "CVE-2006-2238"
  );
  script_bugtraq_id(17074, 17953);

  script_name(english:"Quicktime < 7.1 (Windows)");
  script_summary(english:"Checks version of Quicktime on Windows");
 
  desc = "
Synopsis :

The remote version of QuickTime is affected by multiple overflow
vulnerabilities. 

Description :

The remote Windows host is running a version of Quicktime prior to
7.1. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player. 

See also : 

http://lists.apple.com/archives/security-announce/2006/May/msg00002.html

Solution :

Upgrade to Quicktime version 7.1 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.)") security_warning(get_kb_item("SMB/transport"));
