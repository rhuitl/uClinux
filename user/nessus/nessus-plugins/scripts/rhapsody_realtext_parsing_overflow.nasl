#
# (C) Tenable Network Security
#


if (description) {
  script_id(18560);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(13530);

  name["english"] = "Rhapsody vidplin.dll AVI Processing Heap Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows host contains a multimedia player that is prone to a
buffer overflow attack. 

Description :

The remote installation of Rhapsody has a heap overflow in
RealPlayer's 'vidplin.dll' file used to process AVI files.  With a
specially-crafted AVI file, an attacker can exploit this flaw to cause
arbitrary code to be run within the context of the affected
application when a user opens the file. 

See also : 

http://research.eeye.com/html/advisories/published/AD20050623.html
http://service.real.com/help/faq/security/050623_player/EN/

Solution : 

Upgrade according to the vendor advisory referenced above.

Risk factor : 

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for vidplin.dll AVI processing heap overflow vulnerability in Rhapsody";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("rhapsody_detect.nasl");
  script_require_keys("SMB/Rhapsody/Version");

  exit(0);
}


ver = get_kb_item("SMB/Rhapsody/Version");
if (ver) {
  # There's a problem if it's version 3 with a build in [0.815, 0.1141).
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) == 3 &&
    int(iver[1]) == 0 && 
    int(iver[2]) == 0 &&
    (int(iver[3]) >= 815 && int(iver[3]) < 1141)
  ) security_hole(port);
}
