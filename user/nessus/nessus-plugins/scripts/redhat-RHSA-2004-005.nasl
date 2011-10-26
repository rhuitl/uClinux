#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12447);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0988");

 name["english"] = "RHSA-2004-005: kdepim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdepim packages are now available that fix a local buffer overflow
  vulnerability.

  The K Desktop Environment (KDE) is a graphical desktop for the X Window
  System. The KDE Personal Information Management (kdepim) suite helps you to
  organize your mail, tasks, appointments, and contacts.

  The KDE team found a buffer overflow in the file information reader of
  VCF files. An attacker could construct a VCF file so that when it was
  opened by a victim it would execute arbitrary commands. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0988 to this issue.

  Users of kdepim are advised to upgrade to these erratum packages which
  contain a backported security patch that corrects this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-005.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdepim packages";
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
if ( rpm_check( reference:"kdepim-3.1.3-3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-devel-3.1.3-3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdepim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0988", value:TRUE);
}

set_kb_item(name:"RHSA-2004-005", value:TRUE);
