#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22336);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4381", "CVE-2006-4382", "CVE-2006-4384", "CVE-2006-4385", "CVE-2006-4386", "CVE-2006-4388", "CVE-2006-4389");
  script_bugtraq_id(19976);

  script_name(english:"Quicktime < 7.1.3 (Windows)");
  script_summary(english:"Checks version of Quicktime on Windows");
 
  desc = "
Synopsis :

The remote version of QuickTime is affected by multiple overflow
vulnerabilities. 

Description :

The remote Windows host is running a version of Quicktime prior to
7.1.3. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player. 

See also : 

http://docs.info.apple.com/article.html?artnum=304357

Solution :

Upgrade to Quicktime version 7.1.3 or later.

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.(0\.|1\.[0-2]([^0-9]|$)))"
) security_warning(get_kb_item("SMB/transport"));
