#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12362);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1119");

 name["english"] = "RHSA-2003-048: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An insecure use of a temporary file has been found in Python.

  Python is an interpreted, interactive, object-oriented programming
  language.

  Zack Weinberg discovered that os._execvpe from os.py in Python 2.2.1 and
  earlier creates temporary files with predictable names. This could allow
  local users to execute arbitrary code via a symlink attack

  All users should upgrade to these errata packages which include a patch to
  python 1.5.2 to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-048.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the python packages";
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
if ( rpm_check( reference:"python-1.5.2-43.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-1.5.2-43.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-docs-1.5.2-43.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-1.5.2-43.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-1.5.2-43.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"python-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1119", value:TRUE);
}

set_kb_item(name:"RHSA-2003-048", value:TRUE);
