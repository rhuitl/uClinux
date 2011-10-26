#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22222);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2494");

 name["english"] = "RHSA-2006-0582: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdebase packages that resolve several bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment. These core packages include the file manager Konqueror.

  Ilja van Sprundel discovered a lock file handling flaw in kcheckpass. If
  the directory /var/lock is writable by a user who is allowed to run
  kcheckpass, that user could gain root privileges. In Red Hat Enterprise
  Linux, the /var/lock directory is not writable by users and therefore this
  flaw could only have been exploited if the permissions on that directory
  have been badly configured. A patch to block this issue has been included
  in this update. (CVE-2005-2494)

  The following bugs have also been addressed:

  - kstart --tosystray does not send the window to the system tray in Kicker

  - When the customer enters or selects URLs in Firefox\'s address field, the
  desktop freezes for a couple of seconds

  - fish kioslave is broken on 64-bit systems

  All users of kdebase should upgrade to these updated packages, which
  contain patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0582.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase packages";
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
if ( rpm_check( reference:"kdebase-3.3.1-5.13", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.3.1-5.13", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdebase-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2494", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0582", value:TRUE);
