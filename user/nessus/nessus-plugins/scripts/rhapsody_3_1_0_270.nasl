#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21141);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0323");
  script_bugtraq_id(17202);

  script_name(english:"Rhapsody SWF Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of Rhapsody");
 
  desc = "
Synopsis :

The remote Windows application is affected by a buffer overflow flaw. 

Description :

According to its version number, the installed version of Rhapsody on
the remote host suffers from a buffer overflow involving SWF files. 
To exploit this issue, a remote attacker needs to convince a user to
attempt to play a maliciously-crafted SWF file using the affected
application. 

See also :

http://service.real.com/realplayer/security/03162006_player/en/

Solution :

Upgrade to Rhapsody 3 build 1.0.270 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("rhapsody_detect.nasl");
  script_require_keys("SMB/Rhapsody/Version");

  exit(0);
}


# Check version of Rhapsody.
ver = get_kb_item("SMB/Rhapsody/Version");
if (!ver) exit(0);

# There's a problem if it's version [3.0.0.815, 3.1.0.270).
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) == 3 &&
  (
    (int(iver[1]) == 0 && int(iver[2]) == 0 && int(iver[3]) >= 815) ||
    (int(iver[1]) == 1 && int(iver[2]) == 0 && int(iver[3]) < 270)
  )
) security_warning(get_kb_item("SMB/transport"));
