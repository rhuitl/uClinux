#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21722);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2449");

 name["english"] = "RHSA-2006-0548: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdebase packages that correct a security flaw in kdm are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment. These core packages include the KDE Display Manager (KDM).

  Ludwig Nussel discovered a flaw in KDM. A malicious local KDM user could
  use a symlink attack to read an arbitrary file that they would not normally
  have permissions to read. (CVE-2006-2449)

  Note: this issue does not affect the version of KDM as shipped with Red Hat
  Enterprise Linux 2.1 or 3.

  All users of KDM should upgrade to these updated packages which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0548.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase packages";
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
if ( rpm_check( reference:"kdebase-3.3.1-5.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.3.1-5.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdebase-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2449", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0548", value:TRUE);
