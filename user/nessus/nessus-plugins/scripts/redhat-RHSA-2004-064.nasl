#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12467);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0082");

 name["english"] = "RHSA-2004-064: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Samba packages that fix a security vulnerability are now available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  The Samba team discovered an issue that affects version 3.0.0 and 3.0.1 of
  Samba. If an account for a user is created, but marked as disabled using
  the mksmbpasswd script, it is possible for Samba to overwrite the user\'s
  password with the contents of an uninitialized buffer. This might lead to
  a disabled account becoming enabled with a password that could be guessed
  by an attacker.

  Although this is likely to be a low risk issue for most Samba users, we
  have provided updated packages, which contain a backported patch correcting
  this issue.

  Red Hat would like to thank the Samba team for reporting this issue and
  providing us with a patch.

  Note: Due to a packaging error in samba-3.0.0-14.3E, the winbind daemon is
  not automatically restarted when the Samba package is upgraded. After
  up2date has installed the samba-3.0.2-4.3E packages, you must run
  "/sbin/service winbind condrestart" as root to restart the winbind daemon.




Solution : http://rhn.redhat.com/errata/RHSA-2004-064.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba packages";
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
if ( rpm_check( reference:"samba-3.0.2-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.2-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.2-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.2-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.2-6.3E", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0082", value:TRUE);
}

set_kb_item(name:"RHSA-2004-064", value:TRUE);
