#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22151);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3746");

 name["english"] = "RHSA-2006-0615: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated GnuPG packages that fix a security issue is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GnuPG is a utility for encrypting data and creating digital signatures.

  An integer overflow flaw was found in GnuPG. An attacker could create a
  carefully crafted message packet with a large length that could cause GnuPG
  to crash or possibly overwrite memory when opened. (CVE-2006-3746)

  All users of GnuPG are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0615.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gnupg-1.0.7-18", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.1-17", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.6-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnupg-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3746", value:TRUE);
}
if ( rpm_exists(rpm:"gnupg-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3746", value:TRUE);
}
if ( rpm_exists(rpm:"gnupg-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3746", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0615", value:TRUE);
