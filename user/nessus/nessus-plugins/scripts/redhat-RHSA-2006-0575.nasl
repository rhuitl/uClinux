#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22221);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2006-2275", "CVE-2006-2446", "CVE-2006-2448", "CVE-2006-2934");

 name["english"] = "RHSA-2006-0575:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the fourth regular update to Red Hat Enterprise Linux 4.

  There were several bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 4.

Solution : http://rhn.redhat.com/errata/RHSA-2006-0575.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
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
if ( rpm_check( reference:"kernel-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3055", value:TRUE);
 set_kb_item(name:"CVE-2005-3623", value:TRUE);
 set_kb_item(name:"CVE-2006-0038", value:TRUE);
 set_kb_item(name:"CVE-2006-0456", value:TRUE);
 set_kb_item(name:"CVE-2006-0457", value:TRUE);
 set_kb_item(name:"CVE-2006-0742", value:TRUE);
 set_kb_item(name:"CVE-2006-1052", value:TRUE);
 set_kb_item(name:"CVE-2006-1056", value:TRUE);
 set_kb_item(name:"CVE-2006-1242", value:TRUE);
 set_kb_item(name:"CVE-2006-1343", value:TRUE);
 set_kb_item(name:"CVE-2006-1857", value:TRUE);
 set_kb_item(name:"CVE-2006-2275", value:TRUE);
 set_kb_item(name:"CVE-2006-2446", value:TRUE);
 set_kb_item(name:"CVE-2006-2448", value:TRUE);
 set_kb_item(name:"CVE-2006-2934", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0575", value:TRUE);
