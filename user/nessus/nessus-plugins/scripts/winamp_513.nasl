#
#  (C) Tenable Network Security
#


if (description) {
  script_id(20826);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-3188", "CVE-2006-0476");
  script_bugtraq_id(16410, 16462);
  script_xref(name:"OSVDB", value:"22975");

  script_name(english:"Winamp < 5.13 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks for multiple buffer overflow vulnerabilities in Winamp < 5.13"); 
 
 desc = "
Synopsis :

A multimedia application that is vulnerable to multiple buffer
overflows is installed on the remote Windows host. 

Description :

The remote host is using Winamp, a popular media player for Windows. 

It's possible that a remote attacker using a specially-crafted M3U or
PLS file can cause a buffer overflow in the version of Winamp
installed on the remote Windows host, resulting in a crash of the
application and even execution of arbitrary code remotely subject to
the user's privileges.  Note that these issues can reportedly be
exploited without user interaction by linking to a '.pls' file in an
IFRAME tag. 

See also :

http://www.frsirt.com/exploits/20060129.winamp0day.c.php
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=377
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=378
http://www.winamp.com/player/version_history.php

Solution :

Upgrade to Winamp version 5.13 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");

  exit(0);
}


# Check version of Winamp.
ver = get_kb_item("SMB/Winamp/Version");
if (
  ver && 
  ver =~ "^([0-4]\.|5\.(0\.|1\.[0-2]([^0-9]|$)))"
) {
  security_warning(0);
}
