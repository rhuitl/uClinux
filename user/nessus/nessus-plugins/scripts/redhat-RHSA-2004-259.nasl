#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13658);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0600", "CVE-2004-0686");

 name["english"] = "RHSA-2004-259: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix buffer overflows, as well as other various
  bugs, are now available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  Evgeny Demidov discovered a flaw in the internal routine used by the Samba
  Web Administration Tool (SWAT) in Samba versions 3.0.2 through 3.0.4. When
  decoding base-64 data during HTTP basic authentication, an invalid base-64
  character could cause a buffer overflow. If the SWAT administration
  service is enabled, this flaw could allow an attacker to execute arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0600 to this issue.

  Additionally, the Samba team discovered a buffer overflow in the code used
  to support the \'mangling method = hash\' smb.conf option. Please be aware
  that the default setting for this parameter is \'mangling method = hash2\'
  and therefore not vulnerable. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0686 to this issue.

  This release includes the updated upstream version 3.0.4 together with
  backported security patches to correct these issues as well as a number of
  post-3.0.4 bug fixes from the Samba subversion repository.

  The most important bug fix allows Samba users to change their passwords
  if Microsoft patch KB 828741 (a critical update) had been applied.

  All users of Samba should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-259.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba packages";
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
if ( rpm_check( reference:"samba-3.0.4-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.4-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.4-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.4-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.4-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0600", value:TRUE);
 set_kb_item(name:"CVE-2004-0686", value:TRUE);
}

set_kb_item(name:"RHSA-2004-259", value:TRUE);
