#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19832);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0181", "CVE-2004-1056", "CVE-2005-0124", "CVE-2005-0136", "CVE-2005-0179", "CVE-2005-0210", "CVE-2005-0400", "CVE-2005-0504", "CVE-2005-0756", "CVE-2005-0815", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2490", "CVE-2005-2553", "CVE-2005-2555");

 name["english"] = "RHSA-2005-663:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the sixth
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.


Solution : http://rhn.redhat.com/errata/RHSA-2005-663.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-37.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0181", value:TRUE);
 set_kb_item(name:"CVE-2004-1056", value:TRUE);
 set_kb_item(name:"CVE-2005-0124", value:TRUE);
 set_kb_item(name:"CVE-2005-0136", value:TRUE);
 set_kb_item(name:"CVE-2005-0179", value:TRUE);
 set_kb_item(name:"CVE-2005-0210", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0504", value:TRUE);
 set_kb_item(name:"CVE-2005-0756", value:TRUE);
 set_kb_item(name:"CVE-2005-0815", value:TRUE);
 set_kb_item(name:"CVE-2005-1761", value:TRUE);
 set_kb_item(name:"CVE-2005-1762", value:TRUE);
 set_kb_item(name:"CVE-2005-1767", value:TRUE);
 set_kb_item(name:"CVE-2005-1768", value:TRUE);
 set_kb_item(name:"CVE-2005-2456", value:TRUE);
 set_kb_item(name:"CVE-2005-2490", value:TRUE);
 set_kb_item(name:"CVE-2005-2553", value:TRUE);
 set_kb_item(name:"CVE-2005-2555", value:TRUE);
}

set_kb_item(name:"RHSA-2005-663", value:TRUE);
