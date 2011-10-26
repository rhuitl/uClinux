#
#  (C) Tenable Network Security
#


if (description) {
  script_id(20973);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0708", "CVE-2006-0720");
  script_bugtraq_id(16623, 16785);

  script_name(english:"Winamp < 5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp"); 
 
 desc = "
Synopsis :

A multimedia application that is vulnerable to denial of service
attacks is installed on the remote Windows host. 

Description :

The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
crashes if the user tries to open an M3U file with a long filename. 

In addition, it reportedly contains a buffer overflow flaw that can be
exploited using a specially-crafted M3U file to either crash the
application or possibly even execute arbitrary code remotely. 

See also :

http://www.securityfocus.com/archive/1/424903/30/0/threaded
http://www.securityfocus.com/archive/1/425888/30/0/threaded
http://www.winamp.com/player/version_history.php

Solution :

Upgrade to Winamp version 5.2 or later. 

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


include("smb_func.inc");


# Check version of Winamp.
ver = get_kb_item("SMB/Winamp/Version");
if (
  ver && 
  ver =~ "^([0-4]\.|5\.[01]\.)"
) {
  security_warning(kb_smb_transport());
}
