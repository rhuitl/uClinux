#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21042);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2491");

 name["english"] = "RHSA-2006-0197: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Python packages are now available to correct a security issue.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Python is an interpreted, interactive, object-oriented programming
  language.

  An integer overflow flaw was found in Python\'s PCRE library that could be
  triggered by a maliciously crafted regular expression. On systems that
  accept arbitrary regular expressions from untrusted users, this could be
  exploited to execute arbitrary code with the privileges of the application
  using the library. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2005-2491 to this issue.

  Users of Python should upgrade to these updated packages, which contain a
  backported patch that is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0197.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the python packages";
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
if ( rpm_check( reference:"python-1.5.2-43.72.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-1.5.2-43.72.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-1.5.2-43.72.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-1.5.2-43.72.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-1.5.2-43.72.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-2.2.3-6.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.2.3-6.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.2.3-6.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.3-6.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-2.3.4-14.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.3.4-14.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.3.4-14.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.3.4-14.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.3.4-14.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"python-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
if ( rpm_exists(rpm:"python-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
if ( rpm_exists(rpm:"python-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0197", value:TRUE);
