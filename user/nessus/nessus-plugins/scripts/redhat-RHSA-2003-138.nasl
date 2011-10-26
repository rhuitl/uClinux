#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12387);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0196", "CVE-2003-0201");

 name["english"] = "RHSA-2003-138: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Samba packages that fix a security vulnerability are now available.

  Samba is a suite of utilities which provides file and printer sharing
  services to SMB/CIFS clients.

  A security vulnerability has been found in versions of Samba up to and
  including 2.2.8. An anonymous user could exploit the vulnerability to
  gain root access on the target machine. Note that this is a different
  vulnerability than the one fixed by RHSA-2003:096.

  An exploit for this vulnerability is publicly available.

  All users of Samba are advised to update to the packages listed in this
  erratum, which contain a backported patch correcting this vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2003-138.html
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
if ( rpm_check( reference:"samba-2.2.7-3.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7-3.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7-3.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7-3.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0196", value:TRUE);
 set_kb_item(name:"CVE-2003-0201", value:TRUE);
}

set_kb_item(name:"RHSA-2003-138", value:TRUE);
