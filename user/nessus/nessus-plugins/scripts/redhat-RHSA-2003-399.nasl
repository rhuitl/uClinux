#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12440);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0962");

 name["english"] = "RHSA-2003-399: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated rsync packages are now available that fix a heap overflow in the
  Rsync server.

  rsync is a program for sychronizing files over the network.

  A heap overflow bug exists in rsync versions prior to 2.5.7. On machines
  where the rsync server has been enabled, a remote attacker could use this
  flaw to execute arbitrary code as an unprivileged user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0962 to this issue.

  All users should upgrade to these erratum packages containing version
  2.5.7 of rsync, which is not vulnerable to this issue.

  NOTE: The rsync server is disabled (off) by default in Red Hat Enterprise
  Linux. To check if the rsync server has been enabled (on), run the
  following command:

  /sbin/chkconfig --list rsync

  If the rsync server has been enabled but is not required, it can be
  disabled by running the following command as root:

  /sbin/chkconfig rsync off

  Red Hat would like to thank the rsync team for their rapid response and
  quick fix for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-399.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync packages";
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
if ( rpm_check( reference:"rsync-2.5.7-0.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"rsync-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}
if ( rpm_exists(rpm:"rsync-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}

set_kb_item(name:"RHSA-2003-399", value:TRUE);
