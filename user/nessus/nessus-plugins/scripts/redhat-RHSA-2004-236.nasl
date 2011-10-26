#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12502);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0017");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0523");

 name["english"] = "RHSA-2004-236: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Kerberos 5 (krb5) packages which correct buffer overflows in the
  krb5_aname_to_localname function are now available.

  Kerberos is a network authentication system.

  Bugs have been fixed in the krb5_aname_to_localname library function.
  Specifically, buffer overflows were possible for all Kerberos versions up
  to and including 1.3.3. The krb5_aname_to_localname function translates a
  Kerberos principal name to a local account name, typically a UNIX username.
  This function is frequently used when performing authorization checks.

  If configured with mappings from particular Kerberos principals to
  particular UNIX user names, certain functions called by
  krb5_aname_to_localname will not properly check the lengths of buffers
  used to store portions of the principal name. If configured to map
  principals to user names using rules, krb5_aname_to_localname would
  consistently write one byte past the end of a buffer allocated from the
  heap. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0523 to this issue.

  Only configurations which enable the explicit mapping or rules-based
  mapping functionality of krb5_aname_to_localname() are vulnerable.
  These configurations are not the default.

  Users of Kerberos are advised to upgrade to these erratum packages which
  contain backported security patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-236.html
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
if ( rpm_check( reference:"krb5-devel-1.2.2-27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0523", value:TRUE);
}
if ( rpm_exists(rpm:"krb-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0523", value:TRUE);
}

set_kb_item(name:"RHSA-2004-236", value:TRUE);
