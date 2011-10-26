#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16221);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0971", "CVE-2004-1189");

 name["english"] = "RHSA-2005-012: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Kerberos (krb5) packages that correct buffer overflow and temporary
  file bugs are now available for Red Hat Enterprise Linux.

  Kerberos is a networked authentication system that uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  A heap based buffer overflow bug was found in the administration library of
  Kerberos 1.3.5 and earlier. This bug could allow an authenticated remote
  attacker to execute arbitrary commands on a realm\'s master Kerberos KDC.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1189 to this issue.

  Additionally a temporary file bug was found in the Kerberos krb5-send-pr
  program. It is possible that an attacker could create a temporary file
  that would allow an arbitrary file to be overwritten which the victim has
  write access to. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0971 to this issue.

  All users of krb5 should upgrade to these updated packages, which contain
  backported security patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-012.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
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
if ( rpm_check( reference:"krb5-devel-1.2.2-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-32", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-38", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-38", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-38", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-38", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0971", value:TRUE);
 set_kb_item(name:"CVE-2004-1189", value:TRUE);
}
if ( rpm_exists(rpm:"krb-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0971", value:TRUE);
 set_kb_item(name:"CVE-2004-1189", value:TRUE);
}

set_kb_item(name:"RHSA-2005-012", value:TRUE);
