#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14801);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");

 name["english"] = "RHSA-2004-467: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix two denial of service vulnerabilities are
  now available.

  [Updated 23rd September 2004]
  Packages have been updated to include the ppc64 packages which were left
  out of the initial errata.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  The Samba team has discovered a denial of service bug in the smbd daemon.
  A defect in smbd\'s ASN.1 parsing allows an attacker to send a specially
  crafted packet during the authentication request which will send the newly
  spawned smbd process into an infinite loop. Given enough of these packets,
  it is possible to exhaust the available memory on the server. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0807 to this issue.

  Additionally the Samba team has also discovered a denial of service bug in
  the nmbd daemon. It is possible that an attacker could send a specially
  crafted UDP packet which could allow the attacker to anonymously
  crash nmbd. This issue only affects nmbd daemons which are configured to
  process domain logons. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0808 to this issue.

  Users of Samba should upgrade to these updated packages, which contain an
  upgrade to Samba-3.0.7, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-467.html
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
if ( rpm_check( reference:"samba-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0807", value:TRUE);
 set_kb_item(name:"CVE-2004-0808", value:TRUE);
}

set_kb_item(name:"RHSA-2004-467", value:TRUE);
