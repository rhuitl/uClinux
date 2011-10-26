#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19731);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2798");
 
 name["english"] = "Fedora Core 3 2005-858: openssh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-858 (openssh).

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. SSH
replaces rlogin and rsh, to provide secure encrypted communications
between two untrusted hosts over an insecure network. X11 connections
and arbitrary TCP/IP ports can also be forwarded over the secure
channel. Public key authentication may be used for 'passwordless'
access to servers.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

Update Information:

This security update fixes CVE-2005-2798 and resolves a
problem with X forwarding binding only on IPv6 address on
certain circumstances.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssh package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-3.9p1-8.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.9p1-8.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.9p1-8.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.9p1-8.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openssh-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2798", value:TRUE);
}
