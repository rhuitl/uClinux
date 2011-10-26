#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21090);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0049", "CVE-2006-0455");

 name["english"] = "RHSA-2006-0266: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated GnuPG package that fixes signature verification flaws as well as
  minor bugs is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GnuPG is a utility for encrypting data and creating digital signatures.

  Tavis Ormandy discovered a bug in the way GnuPG verifies cryptographically
  signed data with detached signatures. It is possible for an attacker to
  construct a cryptographically signed message which could appear to come
  from a third party. When a victim processes a GnuPG message with a
  malformed detached signature, GnuPG ignores the malformed signature,
  processes and outputs the signed data, and exits with status 0, just as it
  would if the signature had been valid. In this case, GnuPG\'s exit status
  would not indicate that no signature verification had taken place. This
  issue would primarily be of concern when processing GnuPG results via an
  automated script. The Common Vulnerabilities and Exposures project assigned
  the name CVE-2006-0455 to this issue.

  Tavis Ormandy also discovered a bug in the way GnuPG verifies
  cryptographically signed data with inline signatures. It is possible for an
  attacker to inject unsigned data into a signed message in such a way that
  when a victim processes the message to recover the data, the unsigned data
  is output along with the signed data, gaining the appearance of having been
  signed. This issue is mitigated in the GnuPG shipped with Red Hat
  Enterprise Linux as the --ignore-crc-error option must be passed to the gpg
  executable for this attack to be successful. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2006-0049 to this issue.

  Please note that neither of these issues affect the way RPM or up2date
  verify RPM package files, nor is RPM vulnerable to either of these issues.

  All users of GnuPG are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0266.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg packages";
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
if ( rpm_check( reference:"gnupg-1.0.7-16", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.1-15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.6-3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnupg-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-0049", value:TRUE);
 set_kb_item(name:"CVE-2006-0455", value:TRUE);
}
if ( rpm_exists(rpm:"gnupg-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-0049", value:TRUE);
 set_kb_item(name:"CVE-2006-0455", value:TRUE);
}
if ( rpm_exists(rpm:"gnupg-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0049", value:TRUE);
 set_kb_item(name:"CVE-2006-0455", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0266", value:TRUE);
