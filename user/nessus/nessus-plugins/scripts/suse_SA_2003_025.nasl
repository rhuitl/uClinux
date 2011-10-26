#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13795);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0201");
 
 name["english"] = "SUSE-SA:2003:025: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:025 (samba).


Digital Defense Inc. have discovered a buffer overflow in the samba
file server, the widely spread implementation of the SMB protocol.
The flaw allows a remote attacker to execute arbitrary commands as root
on a server that runs a vulnerable version of samba. The vulnerability
is known as DDI trans2.c overflow bug and is assigned the CVE ID
CVE-2003-0201. Since this vulnerability was found during an analysis of
an exploit happening in the wild, it should be assumed that exploits
are circulating in the internet.

A possible workaround is to restrict access using the 'hosts allow'
directive in the smb.conf file to a group of trusted hosts/addresses
that should be able to access the server. Please see the sbm.conf(5)
manpage ('man smb.conf') for more details about such configuration
changes. It should be noted that each change of the configuration
requires restarting/reloading the samba daemon ('rcsmb reload').

The only efficient and permanent remedy for the vulnerability should
be to install the provided update packages from locations as listed
below.

It should be noted that this announcement is not a re-release of

Solution : http://www.suse.de/security/2003_025_samba.html
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
if ( rpm_check( reference:"samba-2.0.10-32", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smbclnt-2.0.10-32", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.0a-52", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smbclnt-2.2.0a-52", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.1a-220", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.1a-220", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.3a-172", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.3a-172", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.5-178", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.5-178", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.7a-72", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-72", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"SUSE7.1")
 || rpm_exists(rpm:"samba-", release:"SUSE7.2")
 || rpm_exists(rpm:"samba-", release:"SUSE7.3")
 || rpm_exists(rpm:"samba-", release:"SUSE8.0")
 || rpm_exists(rpm:"samba-", release:"SUSE8.1")
 || rpm_exists(rpm:"samba-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0201", value:TRUE);
}
