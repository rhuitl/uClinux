#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15701);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0938", "CVE-2004-0960", "CVE-2004-0961");

 name["english"] = "RHSA-2004-609: freeradius";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated freeradius packages that fix a number of denial of service
  vulnerabilities as well as minor bugs are now available for Red Hat
  Enterprise Linux 3.

  FreeRADIUS is a high-performance and highly configurable free RADIUS server
  designed to allow centralized authentication and authorization for a
  network.

  A number of flaws were found in FreeRADIUS versions prior to 1.0.1. An
  attacker who is able to send packets to the server could construct
  carefully constructed packets in such a way as to cause the server to
  consume memory or crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CVE-2004-0938, CVE-2004-0960, and
  CVE-2004-0961 to these issues.

  Users of FreeRADIUS should update to these erratum packages that contain
  FreeRADIUS 1.0.1, which is not vulnerable to these issues and also corrects
  a number of bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2004-609.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the freeradius packages";
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
if ( rpm_check( reference:"freeradius-1.0.1-1.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"freeradius-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0938", value:TRUE);
 set_kb_item(name:"CVE-2004-0960", value:TRUE);
 set_kb_item(name:"CVE-2004-0961", value:TRUE);
}

set_kb_item(name:"RHSA-2004-609", value:TRUE);
