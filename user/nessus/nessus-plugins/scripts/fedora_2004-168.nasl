#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13722);
 script_bugtraq_id(10412);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0412");
 
 name["english"] = "Fedora Core 2 2004-168: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-168 (mailman).

Mailman is software to help manage email discussion lists, much like
Majordomo and Smartmail. Unlike most similar products, Mailman gives
each mailing list a webpage, and allows users to subscribe,
unsubscribe, etc. over the Web. Even the list manager can administer
his or her list entirely from the Web. Mailman also integrates most
things people want to do with mailing lists, including archiving, mail
<-> news gateways, and so on.

Documentation can be found in: /usr/share/doc/mailman-2.1.5

When the package has finished installing, you will need to perform some
additional installation steps, these are described in:
/usr/share/doc/mailman-2.1.5/INSTALL.REDHAT

Update Information:

Fixes security issue CVE-2004-0412 noted in bug
https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=123559
 
Mailman subscriber passwords could be retrieved by a remote attacker.
Security hole is fixed in mailman-2.1.5

Important Installation Note:

Some users have reported problems with bad queue counts after
upgrading to version 2.1.5, the operating assumption is this was
caused by performing an install while mailman was running. Prior to
installing this rpm stop the mailman service via:

% /sbin/service mailman stop

Then after installation completes restart the service via:

% /sbin/service mailman start

Red Hat RPM versions of mailman 2.1.5-6 and above have enhanced the
init.d script that controls the mailman service so that '/sbin/service
mailman status' now returns valid information. The RPM has been
augmented to detect if mailman is running prior to installation and if
so it will temporarily stop mailman during the install and restart
mailman after the install completes. If mailman was not running the
RPM will not start mailman after installation. Since the RPM depends
on service status working the installed version of mailman you are
replacing must be at least 2.1.5-6 for the automatic pausing of
mailman during installation to work. This also means since this is the
first RPM with this feature you will need to manually pause mailman
during installation, future upgrades should be automatic.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-168.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mailman-2.1.5-7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-debuginfo-2.1.5-7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mailman-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0412", value:TRUE);
}
