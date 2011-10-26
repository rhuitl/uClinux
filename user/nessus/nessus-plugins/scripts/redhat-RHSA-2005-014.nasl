#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16147);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0946", "CVE-2004-1014");

 name["english"] = "RHSA-2005-014: nfs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated nfs-utils package that fixes various security issues is now
  available.

  The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  SGI reported that the statd daemon did not properly handle the SIGPIPE
  signal. A misconfigured or malicious peer could cause statd to crash,
  leading to a denial of service. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-1014 to this issue.

  Arjan van de Ven discovered a buffer overflow in rquotad. On 64-bit
  architectures, an improper integer conversion can lead to a buffer
  overflow. An attacker with access to an NFS share could send a specially
  crafted request which could lead to the execution of arbitrary code. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0946 to this issue.

  All users of nfs-utils should upgrade to this updated package, which
  resolves these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-014.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nfs packages";
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
if ( rpm_check( reference:"nfs-utils-0.3.3-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"nfs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0946", value:TRUE);
 set_kb_item(name:"CVE-2004-1014", value:TRUE);
}

set_kb_item(name:"RHSA-2005-014", value:TRUE);
