#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12319);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0821", "CVE-2002-0822", "CVE-2002-0834", "CVE-2002-0402", "CVE-2002-0403", "CVE-2002-0404");

 name["english"] = "RHSA-2002-170: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ethereal packages are available which fix several security problems.

  Ethereal is a package designed for monitoring network traffic on your
  system. Several security issues have been found in the Ethereal packages
  distributed with Red Hat Linux Advanced Server:

  Buffer overflow in Ethereal 0.9.5 and earlier allows remote attackers to
  cause a denial of service or execute arbitrary code via the ISIS dissector.
  (CVE-2002-0834)

  Buffer overflows in Ethereal 0.9.4 and earlier allows remote attackers
  to cause a denial of service or execute arbitrary code via (1) the BGP
  dissector, or (2) the WCP dissector. (CVE-2002-0821)

  Ethereal 0.9.4 and earlier allows remote attackers to cause a denial
  of service and possibly excecute arbitrary code via the (1) SOCKS, (2)
  RSVP, (3) AFS, or (4) LMP dissectors, which can be caused to core
  dump (CVE-2002-0822)

  A buffer overflow in the X11 dissector in Ethereal before 0.9.4 allows
  remote attackers to cause a denial of service (crash) and possibly
  execute arbitrary code while Ethereal is parsing keysyms. (CVE-2002-0402)

  The DNS dissector in Ethereal before 0.9.4 allows remote attackers to
  cause a denial of service (CPU consumption) via a malformed packet
  that causes Ethereal to enter an infinite loop. (CVE-2002-0403)

  A vulnerability in the GIOP dissector in Ethereal before 0.9.4 allows
  remote attackers to cause a denial of service (memory consumption).
  (CVE-2002-0404)

  Users of Ethereal should update to the errata packages containing Ethereal
  version 0.9.6 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-170.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.9.6-0.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.6-0.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0821", value:TRUE);
 set_kb_item(name:"CVE-2002-0822", value:TRUE);
 set_kb_item(name:"CVE-2002-0834", value:TRUE);
 set_kb_item(name:"CVE-2002-0402", value:TRUE);
 set_kb_item(name:"CVE-2002-0403", value:TRUE);
 set_kb_item(name:"CVE-2002-0404", value:TRUE);
}

set_kb_item(name:"RHSA-2002-170", value:TRUE);
