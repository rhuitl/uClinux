#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19213);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-2154");

 name["english"] = "RHSA-2005-571: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fix a security issue are now available for Red
  Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for
  UNIX(R) operating systems.

  When processing a request, the CUPS scheduler would use case-sensitive
  matching on the queue name to decide which authorization policy should be
  used. However, queue names are not case-sensitive. An unauthorized user
  could print to a password-protected queue without needing a password. The
  Common Vulnerabilities and Exposures project has assigned the name
  CVE-2005-2154 to this issue.

  Please note that the version of CUPS included in Red Hat Enterprise Linux 4
  is not vulnerable to this issue.

  All users of CUPS should upgrade to these erratum packages which contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-571.html
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
if ( rpm_check( reference:"cups-1.1.17-13.3.29", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.29", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.29", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-2154", value:TRUE);
}

set_kb_item(name:"RHSA-2005-571", value:TRUE);
