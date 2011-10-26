#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20361);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3631");

 name["english"] = "RHSA-2005-864: udev";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated udev packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The udev package contains an implementation of devfs in userspace using
  sysfs and /sbin/hotplug.

  Richard Cunningham discovered a flaw in the way udev sets permissions on
  various files in /dev/input. It may be possible for an authenticated
  attacker to gather sensitive data entered by a user at the console, such as
  passwords. The Common Vulnerabilities and Exposures project has assigned
  the name CVE-2005-3631 to this issue.

  All users of udev should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-864.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the udev packages";
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
if ( rpm_check( reference:"udev-039-10.10.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"udev-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3631", value:TRUE);
}

set_kb_item(name:"RHSA-2005-864", value:TRUE);
