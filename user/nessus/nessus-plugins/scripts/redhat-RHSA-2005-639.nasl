#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19286);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1852");

 name["english"] = "RHSA-2005-639: kdenetwork";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdenetwork packages to correct a security flaw in Kopete are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The kdenetwork package contains networking applications for the K Desktop
  Environment. Kopete is a KDE instant messenger which supports a number of
  protocols including ICQ, MSN, Yahoo, Jabber, and Gadu-Gadu.

  Multiple integer overflow flaws were found in the way Kopete processes
  Gadu-Gadu messages. A remote attacker could send a specially crafted
  Gadu-Gadu message which would cause Kopete to crash or possibly execute
  arbitrary code. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2005-1852 to this issue.

  In order to be affected by this issue, a user would need to have registered
  with Gadu-Gadu and be signed in to the Gadu-Gadu server in order to receive
  a malicious message. In addition, Red Hat believes that the Exec-shield
  technology (enabled by default in Red Hat Enterprise Linux 4) would block
  attempts to remotely exploit this vulnerability.

  Note that this issue does not affect Red Hat Enterprise Linux 2.1 or 3.

  Users of Kopete should update to these packages which contain a
  patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-639.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdenetwork packages";
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
if ( rpm_check( reference:"kdenetwork-3.3.1-2.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.3.1-2.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-nowlistening-3.3.1-2.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdenetwork-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1852", value:TRUE);
}

set_kb_item(name:"RHSA-2005-639", value:TRUE);
