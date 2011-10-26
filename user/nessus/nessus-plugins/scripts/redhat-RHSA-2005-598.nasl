#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19409);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2104");

 name["english"] = "RHSA-2005-598: sysreport";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated sysreport package that fixes an insecure temporary file flaw is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Sysreport is a utility that gathers information about a system\'s hardware
  and configuration. The information can then be used for diagnostic purposes
  and debugging.

  Bill Stearns discovered a bug in the way sysreport creates temporary files.
  It is possible that a local attacker could obtain sensitive information
  about the system when sysreport is run. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-2104 to this issue.

  Users of sysreport should update to this erratum package, which contains a
  patch that resolves this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-598.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   sysreport packages";
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
if ( rpm_check( reference:"sysreport-1.3.7.0-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sysreport-1.3.15-5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sysreport-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2104", value:TRUE);
}
if ( rpm_exists(rpm:"sysreport-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2104", value:TRUE);
}

set_kb_item(name:"RHSA-2005-598", value:TRUE);
