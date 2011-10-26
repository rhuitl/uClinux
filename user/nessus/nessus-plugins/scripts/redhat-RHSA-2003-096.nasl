#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12379);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0085", "CVE-2003-0086");

 name["english"] = "RHSA-2003-096: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Samba packages are now available to fix security vulnerabilities
  found during a code audit.

  Samba is a suite of utilities which provides file and printer sharing
  services to SMB/CIFS clients.

  Sebastian Krahmer discovered a security vulnerability present
  in unpatched versions of Samba prior to 2.2.8. An anonymous user could use
  the vulnerability to gain root access on the target machine.

  Additionally, a race condition could allow an attacker to overwrite
  critical system files.

  All users of Samba are advised to update to the erratum packages which
  contain patches to correct these vulnerabilities.

  These packages contain the security fixes backported to the Samba 2.2.7
  codebase.




Solution : http://rhn.redhat.com/errata/RHSA-2003-096.html
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
if ( rpm_check( reference:"samba-2.2.7-2.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7-2.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7-2.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7-2.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0085", value:TRUE);
 set_kb_item(name:"CVE-2003-0086", value:TRUE);
}

set_kb_item(name:"RHSA-2003-096", value:TRUE);
