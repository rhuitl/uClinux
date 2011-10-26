#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22112);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3403");

 name["english"] = "RHSA-2006-0591: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix a denial of service vulnerability are now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  A denial of service bug was found in the way the smbd daemon tracks active
  connections to shares. It was possible for a remote attacker to cause the
  smbd daemon to consume a large amount of system memory by sending carefully
  crafted smb requests. (CVE-2006-3403)

  Users of Samba are advised to upgrade to these packages, which
  contain a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0591.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba packages";
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
if ( rpm_check( reference:"samba-2.2.12-1.21as.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.9-1.3E.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.9-1.3E.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.9-1.3E.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.9-1.3E.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.10-1.4E.6.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.10-1.4E.6.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.10-1.4E.6.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.10-1.4E.6.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3403", value:TRUE);
}
if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3403", value:TRUE);
}
if ( rpm_exists(rpm:"samba-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3403", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0591", value:TRUE);
