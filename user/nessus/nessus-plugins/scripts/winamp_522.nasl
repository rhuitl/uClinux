#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21733);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18507);

  script_name(english:"Winamp Malformed Midi File Buffer Overflow Vulnerability");
  script_summary(english:"Checks the version number of Winamp"); 
 
 desc = "
Synopsis :

The remote Windows host contains a multimedia application that is
prone to a buffer overflow attack. 

Description :

The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
contains a buffer overflow in the 'in_midi.dll' library that can be
exploited using a specially-crafted MIDI file to either crash the
affected application or possibly even execute arbitrary code remotely,
subject to the privileges of the user running the application. 

See also :

http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-16.html
http://www.winamp.com/player/version_history.php

Solution :

Upgrade to Winamp version 5.22 or later. 

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");

  exit(0);
}


# Check version of Winamp.
#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client might report.
ver = get_kb_item("SMB/Winamp/Version");
if (ver && ver =~ "^([0-4]\.|5\.([01]\.|2\.[01]\.))") 
  security_hole(get_kb_item("SMB/transport"));
