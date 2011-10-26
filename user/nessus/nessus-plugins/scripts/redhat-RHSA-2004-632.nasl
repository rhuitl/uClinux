#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15741);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0882", "CVE-2004-0930");

 name["english"] = "RHSA-2004-632: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix various security vulnerabilities are now
  available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  During a code audit, Stefan Esser discovered a buffer overflow in Samba
  versions prior to 3.0.8 when handling unicode filenames. An authenticated
  remote user could exploit this bug which may lead to arbitrary code
  execution on the server. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0882 to this issue. Red Hat
  believes that the Exec-Shield technology (enabled by default since Update
  3) will block attempts to remotely exploit this vulnerability on x86
  architectures.

  Additionally, a bug was found in the input validation routines in versions
  of Samba prior to 3.0.8 that caused the smbd process to consume abnormal
  amounts of system memory. An authenticated remote user could exploit this
  bug to cause a denial of service. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0930 to this issue.

  Users of Samba should upgrade to these updated packages, which contain
  backported security patches, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-632.html
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
if ( rpm_check( reference:"samba-2.2.12-1.21as.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0882", value:TRUE);
 set_kb_item(name:"CVE-2004-0930", value:TRUE);
}
if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0882", value:TRUE);
 set_kb_item(name:"CVE-2004-0930", value:TRUE);
}

set_kb_item(name:"RHSA-2004-632", value:TRUE);
