#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21286);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3732");

 name["english"] = "RHSA-2006-0267: ipsec";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ipsec-tools packages that fix a bug in racoon are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ipsec-tools package is used in conjunction with the IPsec functionality
  in the linux kernel and includes racoon, an IKEv1 keying daemon.

  A denial of service flaw was found in the ipsec-tools racoon daemon. If a
  victim\'s machine has racoon configured in a non-recommended insecure
  manner, it is possible for a remote attacker to crash the racoon daemon.
  (CVE-2005-3732)

  Users of ipsec-tools should upgrade to these updated packages, which contain
  backported patches, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0267.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ipsec-tools-0.2.5-0.7.rhel3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.3.3-6.rhel4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ipsec-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3732", value:TRUE);
}
if ( rpm_exists(rpm:"ipsec-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3732", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0267", value:TRUE);
