#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14737);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0558");

 name["english"] = "RHSA-2004-449: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated cups packages that fix a denial of service vulnerability are now
  available.

  The Common UNIX Printing System (CUPS) is a print spooler.

  Alvaro Martinez Echevarria reported a bug in the CUPS Internet Printing
  Protocol (IPP) implementation in versions of CUPS prior to 1.1.21. An
  attacker could send a carefully crafted UDP packet to the IPP port which
  could cause CUPS to stop listening to the port and result in a denial of
  service. In order to exploit this bug, an attacker would need to have the
  ability to send a UDP packet to the IPP port (by default 631). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0558 to this issue.

  All users of cups should upgrade to these updated packages, which contain a
  backported patch as well as a fix for a non-exploitable off-by-one bug.




Solution : http://rhn.redhat.com/errata/RHSA-2004-449.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups packages";
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
if ( rpm_check( reference:"cups-1.1.17-13.3.13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.13", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0558", value:TRUE);
}

set_kb_item(name:"RHSA-2004-449", value:TRUE);
