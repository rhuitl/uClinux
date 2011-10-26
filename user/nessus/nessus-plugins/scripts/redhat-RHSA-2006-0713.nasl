#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22525);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4980");

 name["english"] = "RHSA-2006-0713: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Python packages are now available to correct a security issue in
  Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Python is an interpreted, interactive, object-oriented programming
  language.

  A flaw was discovered in the way that the Python repr() function handled
  UTF-32/UCS-4 strings. If an application written in Python used the repr()
  function on untrusted data, this could lead to a denial of service or
  possibly allow the execution of arbitrary code with the privileges of the
  Python application. (CVE-2006-4980)

  In addition, this errata fixes a regression in the SimpleXMLRPCServer
  backport for Red Hat Enterprise Linux 3 that was introduced with
  RHSA-2005:109.

  Users of Python should upgrade to these updated packages, which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0713.html
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
if ( rpm_check( reference:"python-2.2.3-6.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.2.3-6.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.2.3-6.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.3-6.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-2.3.4-14.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.3.4-14.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-2.3.4-14.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.3.4-14.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.3.4-14.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"python-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4980", value:TRUE);
}
if ( rpm_exists(rpm:"python-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4980", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0713", value:TRUE);
