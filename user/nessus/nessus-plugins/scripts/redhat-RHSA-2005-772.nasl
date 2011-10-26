#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19834);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2874");

 name["english"] = "RHSA-2005-772: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fix a security issue are now available for Red
  Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  A bug was found in the way CUPS processes malformed HTTP requests. It is
  possible for a remote user capable of connecting to the CUPS daemon to
  issue a malformed HTTP GET request that causes CUPS to enter an
  infinite loop. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-2874 to this issue.

  Two small bugs have also been fixed in this update. A signal handling
  problem has been fixed that could occasionally cause the scheduler to stop
  when told to reload. A problem with tracking open file descriptors under
  certain specific circumstances has also been fixed.

  All users of CUPS should upgrade to these erratum packages, which contain a
  patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-772.html
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
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2874", value:TRUE);
}

set_kb_item(name:"RHSA-2005-772", value:TRUE);
