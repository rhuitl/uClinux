#
# (C) Tenable Network Security
#


if (description) {
  script_id(19217);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2310");
  script_bugtraq_id(14276);

  name["english"] = "Winamp Malformed ID3v2 Tag Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

A multimedia application that is affected by a buffer overflow
vulnerability is installed on the remote Windows host.

Description :

The remote host is using Winamp, a popular media player for Windows.

The installed version of Winamp suffers from a buffer overflow
vulnerability when processing overly-long ID3v2 tags in an MP3 file. 
An attacker may be able to exploit this flaw to execute arbitrary code
on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/405280/30/0/threaded

Solution : 

Upgrade to Winamp version 5.093 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for malformed ID3v2 tag buffer overflow vulnerability in Winamp";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");

  exit(0);
}


ver = get_kb_item("SMB/Winamp/Version");
if (
  ver && 
  # nb: versions < 5.093 are possibly affected.
  ver =~ "^([0-4]\.|5\.0\.([0-8]\.|9\.[0-2]))"
) {
  security_hole(0);
}
