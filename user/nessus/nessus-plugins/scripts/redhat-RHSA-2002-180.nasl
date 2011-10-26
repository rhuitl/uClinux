#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12321);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0825", "CVE-2002-0374");

 name["english"] = "RHSA-2002-180: nss_ldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated nss_ldap packages are now available for Red Hat Linux Advanced
  Server 2.1. These updates fix a potential buffer overflow which can occur
  when nss_ldap is set to configure itself using information stored in DNS
  as well as a format string bug in logging functions used in pam_ldap.

  [Updated 09 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  nss_ldap is a set of C library extensions that allow X.500 and LDAP
  directory servers to be used as a primary source of aliases, ethers,
  groups, hosts, networks, protocols, users, RPCs, services, and shadow
  passwords (instead of or in addition to using flat files or NIS).

  When versions of nss_ldap prior to nss_ldap-198 are configured without a
  value for the "host" setting, nss_ldap will attempt to configure itself by
  using SRV records stored in DNS. When parsing the results of the DNS
  query, nss_ldap does not check that data returned by the server will fit
  into an internal buffer, leaving it vulnerable to a buffer overflow
  The Common Vulnerabilities and Exposures project has assigned the name
  CVE-2002-0825 to this issue.

  When versions of nss_ldap prior to nss_ldap-199 are configured without a
  value for the "host" setting, nss_ldap will attempt to configure itself by
  using SRV records stored in DNS. When parsing the results of the DNS
  query, nss_ldap does not check that the data returned has not been
  truncated by the resolver libraries to avoid a buffer overflow, and may
  attempt to parse more data than is actually available, leaving it
  vulnerable to a read buffer overflow.

  Versions of pam_ldap prior to version 144 include a format string bug in
  the logging function. The packages included in this erratum update pam_ldap
  to version 144, fixing this bug. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2002-0374 to this issue.

  All users of nss_ldap should update to these errata packages which are not
  vulnerable to the above issues. These packages are based on nss_ldap-189
  with the addition of a backported security patch and pam_ldap version 144.

  Thanks to the nss_ldap and pam_ldap team at padl.com for providing
  information about these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2002-180.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nss_ldap packages";
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
if ( rpm_check( reference:"nss_ldap-189-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"nss_ldap-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0825", value:TRUE);
 set_kb_item(name:"CVE-2002-0374", value:TRUE);
}

set_kb_item(name:"RHSA-2002-180", value:TRUE);
