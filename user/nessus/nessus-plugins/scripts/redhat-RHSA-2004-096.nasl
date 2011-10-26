#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12475);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0148", "CVE-2004-0185");

 name["english"] = "RHSA-2004-096: wu";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated wu-ftpd package that fixes two security issues is now available.

  The wu-ftpd package contains the Washington University FTP (File Transfer
  Protocol) server daemon. FTP is a method of transferring files between
  machines.

  Glenn Stewart discovered a flaw in wu-ftpd. When configured with
  "restricted-gid home", an authorized user could use this flaw to
  circumvent the configured home directory restriction by using chmod. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0148 to this issue.

  Michael Hendrickx found a flaw in the S/Key login handling. On servers
  using S/Key authentication, a remote attacker could overflow a buffer and
  potentially execute arbitrary code.

  Users of wu-ftpd are advised to upgrade to this updated package, which
  contains backported security patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-096.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wu packages";
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
if ( rpm_check( reference:"wu-ftpd-2.6.1-22", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wu-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0148", value:TRUE);
 set_kb_item(name:"CVE-2004-0185", value:TRUE);
}

set_kb_item(name:"RHSA-2004-096", value:TRUE);
