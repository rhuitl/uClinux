#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14697);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0694", "CVE-2004-0745", "CVE-2004-0769", "CVE-2004-0771");

 name["english"] = "RHSA-2004-440: lha";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated lha package that fixes a buffer overflow is now available.

  LHA is an archiving and compression utility for LHarc format archives.

  Lukasz Wojtow discovered a stack-based buffer overflow in all versions
  of lha up to and including version 1.14. A carefully created archive could
  allow an attacker to execute arbitrary code when a victim extracts or tests
  the archive. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0769 to this issue.

  Buffer overflows were discovered in the command line processing of all
  versions of lha up to and including version 1.14. If a malicious user can
  trick a victim into passing a specially crafted command line to the lha
  command, it is possible that arbitrary code could be executed. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CVE-2004-0771 and CVE-2004-0694 to these issues.

  Thomas Biege discovered a shell meta character command execution
  vulnerability in all versions of lha up to and including 1.14. An attacker
  could create a directory with shell meta characters in its name which could
  lead to arbitrary command execution. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0745 to
  this issue.

  Users of lha should update to this updated package which contains
  backported patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-440.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lha packages";
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
if ( rpm_check( reference:"lha-1.00-17.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"lha-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0694", value:TRUE);
 set_kb_item(name:"CVE-2004-0745", value:TRUE);
 set_kb_item(name:"CVE-2004-0769", value:TRUE);
 set_kb_item(name:"CVE-2004-0771", value:TRUE);
}

set_kb_item(name:"RHSA-2004-440", value:TRUE);
