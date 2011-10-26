#
# (C) Tenable Network Security
#


if (description) {
  script_id(18299);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1655");
  script_bugtraq_id(13553);

  name["english"] = "AIM Smiley Icon Location Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows application is prone to denial of service attacks. 

Description :

According to the Windows registry, the remote host has installed on it a
version of AOL Instant Messenger that does not properly handle invalid
data passed as the location of a 'smiley' icon.  Such invalid data leads
to an application crash, possibly because of a buffer overflow. 

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for smiley icon location denial of service vulnerability in AIM";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (ver) {
  # There's a problem if the newest version is 5.9.3702 or below.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 && 
      (
        int(iver[1]) < 9 ||
        (int(iver[1]) == 9 && int(iver[2]) <= 3702)
      )
    )
  ) security_note(port);
}
