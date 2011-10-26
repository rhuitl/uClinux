#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:035
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15423);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0815");
 
 name["english"] = "SUSE-SA:2004:035: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:035 (samba).


The Samba server, which allows to share files and resources via
the SMB/CIFS protocol, contains a bug in the sanitation code of path
names which allows remote attackers to access files outside of the
defined share. In order to access these files, they must be readable
by the account used for the SMB session.
CVE-2004-0815 has been assigned to this issue.


Solution : http://www.suse.de/security/2004_35_samba.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"samba-2.2.8a-224", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-225", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-226", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"SUSE8.1")
 || rpm_exists(rpm:"samba-", release:"SUSE8.2")
 || rpm_exists(rpm:"samba-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2004-0815", value:TRUE);
}
