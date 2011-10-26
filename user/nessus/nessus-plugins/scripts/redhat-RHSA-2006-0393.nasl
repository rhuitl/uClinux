#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22220);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2496");

 name["english"] = "RHSA-2006-0393: ntp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ntp packages that fix several bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The Network Time Protocol (NTP) is used to synchronize a computer\'s time
  with a reference time source.

  The NTP daemon (ntpd), when run with the -u option and using a string to
  specify the group, uses the group ID of the user instead of the group,
  which causes ntpd to run with different privileges than intended.
  (CVE-2005-2496)

  The following issues have also been addressed in this update:
  - The init script had several problems
  - The script executed on upgrade could fail
  - The man page for ntpd indicated the wrong option for specifying a chroot
  directory
  - The ntp daemon could crash with the message "Exiting: No more memory!"
  - There is a new option for syncing the hardware clock after a successful
  run of ntpdate

  Users of ntp should upgrade to these updated packages, which resolve these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0393.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ntp packages";
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
if ( rpm_check( reference:"ntp-4.2.0.a.20040617-4.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ntp-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2496", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0393", value:TRUE);
