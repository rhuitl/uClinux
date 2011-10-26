#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15441);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0884");

 name["english"] = "RHSA-2004-546: cyrus";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated cyrus-sasl packages that fix a setuid and setgid application
  vulnerability are now available.

  [Updated 7th October 2004]
  Revised cryus-sasl packages have been added for Red Hat Enterprise Linux 3;
  the patch in the previous packages broke interaction with ldap.

  The cyrus-sasl package contains the Cyrus implementation of SASL. SASL is
  the Simple Authentication and Security Layer, a method for adding
  authentication support to connection-based protocols.

  At application startup, libsasl and libsasl2 attempts to build a list
  of all available SASL plug-ins which are available on the system. To do
  so, the libraries search for and attempt to load every shared library found
  within the plug-in directory. This location can be set with the SASL_PATH
  environment variable.

  In situations where an untrusted local user can affect the environment of a
  privileged process, this behavior could be exploited to run arbitrary code
  with the privileges of a setuid or setgid application. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0884 to this issue.

  Users of cyrus-sasl should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-546.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus packages";
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
if ( rpm_check( reference:"cyrus-sasl-1.5.24-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-devel-1.5.24-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-1.5.24-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-md5-1.5.24-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-1.5.24-26", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-devel-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-md5-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-2.1.15-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cyrus-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0884", value:TRUE);
}
if ( rpm_exists(rpm:"cyrus-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0884", value:TRUE);
}

set_kb_item(name:"RHSA-2004-546", value:TRUE);
