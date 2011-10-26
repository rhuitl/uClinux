#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20046);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2069", "CVE-2005-2641");

 name["english"] = "RHSA-2005-767: compat";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openldap and nss_ldap packages that correct a potential password
  disclosure issue and possible authentication vulnerability are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  The nss_ldap module is an extension for use with GNU libc which allows
  applications to, without internal modification, consult a directory service
  using LDAP to supplement information that would be read from local files
  such as /etc/passwd, /etc/group, and /etc/shadow.

  A bug was found in the way OpenLDAP, nss_ldap, and pam_ldap refer LDAP
  servers. If a client connection is referred to a different server, it is
  possible that the referred connection will not be encrypted even if the
  client has "ssl start_tls" in its ldap.conf file. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-2069
  to this issue.

  A bug was found in the way the pam_ldap module processed certain failure
  messages. If the server includes supplemental data in an authentication
  failure result message, but the data does not include any specific error
  code, the pam_ldap module would proceed as if the authentication request
  had succeeded, and authentication would succeed. The Common Vulnerabilities
  and Exposures project has assigned the name CVE-2005-2641 to this issue.

  Additionally the following issues are corrected in this erratum.

  - The OpenLDAP upgrading documentation has been updated.

  - Fix a database deadlock locking issue.

  - A fix where slaptest segfaults on exit after successful check.

  - The library libslapd_db-4.2.so is now located in an
  architecture-dependent directory.

  - The LDAP client no longer enters an infinite loop when the server returns
  a reference to itself.

  - The pam_ldap module adds the ability to check user passwords using a
  directory server to PAM-aware applications.

  - The directory server can now include supplemental information regarding
  the state of the user\'s account if a client indicates that it supports
  such a feature.

  All users of OpenLDAP and nss_ldap are advised to upgrade to these updated
  packages, which contain backported fixes that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-767.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the compat packages";
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
if ( rpm_check( reference:"compat-openldap-2.1.30-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-226-10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-2.2.13-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.2.13-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.2.13-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.2.13-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-sql-2.2.13-4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"compat-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2069", value:TRUE);
 set_kb_item(name:"CVE-2005-2641", value:TRUE);
}

set_kb_item(name:"RHSA-2005-767", value:TRUE);
