#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22345);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1168");

 name["english"] = "RHSA-2006-0663: ncompress";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ncompress packages that address a security issue and fix bugs are
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The ncompress package contains file compression and decompression
  utilities, which are compatible with the original UNIX compress utility (.Z
  file extensions).

  Tavis Ormandy of the Google Security Team discovered a lack of bounds
  checking in ncompress. An attacker could create a carefully crafted file
  that could execute arbitrary code if uncompressed by a victim.
  (CVE-2006-1168)

  In addition, two bugs that affected Red Hat Enterprise Linux 4 ncompress
  packages were fixed:

  * The display statistics and compression results in verbose mode were not
  shown when operating on zero length files.

  * An attempt to compress zero length files resulted in an unexpected return
  code.

  Users of ncompress are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0663.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ncompress packages";
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
if ( rpm_check( reference:"ncompress-4.2.4-38.rhel2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ncompress-4.2.4-39.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ncompress-4.2.4-43.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ncompress-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-1168", value:TRUE);
}
if ( rpm_exists(rpm:"ncompress-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-1168", value:TRUE);
}
if ( rpm_exists(rpm:"ncompress-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1168", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0663", value:TRUE);
