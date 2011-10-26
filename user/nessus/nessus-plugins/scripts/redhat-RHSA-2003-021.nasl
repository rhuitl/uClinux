#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12353);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0016");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0041");

 name["english"] = "RHSA-2003-021: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated packages fix a vulnerability found in the Kerberos FTP client
  distributed with the Red Hat Linux Advanced Server krb5 packages.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1. For Advanced
  Workstation 2.1 these packages also fix CVE-2002-1235 as described in
  RHSA-2002:250

  Kerberos is a network authentication system.

  A problem has been found in the Kerberos FTP client. When retrieving a
  file with a name beginning with a pipe character, the FTP client will
  pass the file name to the command shell in a system() call. This could
  allow a malicious FTP server to write to files outside of the current
  directory or execute commands as the user running the FTP client.

  The Kerberos FTP client runs as the default FTP client when the Kerberos
  package krb5-workstation is installed on a Red Hat Linux Advanced Server
  distribution.

  All users of Kerberos are advised to upgrade to these errata packages which
  contain a backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-021.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
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
if ( rpm_check( reference:"krb5-devel-1.2.2-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0041", value:TRUE);
}

set_kb_item(name:"RHSA-2003-021", value:TRUE);
