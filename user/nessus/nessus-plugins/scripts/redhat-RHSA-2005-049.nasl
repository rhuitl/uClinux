#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16297);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0064");

 name["english"] = "RHSA-2005-049: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fixes a security issue are now available.

  The Common UNIX Printing System provides a portable printing layer for
  UNIX(R) operating systems.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects the CUPS pdftops filter due to a shared codebase.
  An attacker who has the ability to send a malicious PDF file to a printer
  could possibly execute arbitrary code as the "lp" user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0064 to this issue.

  Red Hat believes that the Exec-Shield technology (enabled by default since
  Update 3) will block attempts to remotely exploit these buffer overflow
  vulnerabilities on x86 architectures.

  All users of cups should upgrade to these updated packages, which resolve
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-049.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups packages";
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
if ( rpm_check( reference:"cups-1.1.17-13.3.24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
}

set_kb_item(name:"RHSA-2005-049", value:TRUE);
