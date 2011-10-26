#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19987);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1038");

 name["english"] = "RHSA-2005-361: vixie";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated vixie-cron package that fixes various bugs and a security issue
  is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The vixie-cron package contains the Vixie version of cron. Cron is a
  standard UNIX daemon that runs specified programs at scheduled times.

  A bug was found in the way vixie-cron installs new crontab files. It is
  possible for a local attacker to execute the crontab command in such a way
  that they can view the contents of another user\'s crontab file. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-1038 to
  this issue.

  Additionally, this update addresses the following issues:

  o Fixed improper limits on filename and command line lengths
  o Improved PAM access control conforming to EAL certification requirements
  o Improved reliability when running in a chroot environment
  o Mail recipient name checking disabled by default, can be re-enabled
  o Added \'-p\' "permit all crontabs" option to disable crontab mode checking

  All users of vixie-cron should upgrade to this updated package, which
  contains backported patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-361.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vixie packages";
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
if ( rpm_check( reference:"vixie-cron-4.1-36.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vixie-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1038", value:TRUE);
}

set_kb_item(name:"RHSA-2005-361", value:TRUE);
