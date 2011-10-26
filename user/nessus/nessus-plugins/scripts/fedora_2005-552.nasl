#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18684);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
 
 name["english"] = "Fedora Core 3 2005-552: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-552 (krb5).

Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

Update Information:

A double-free flaw was found in the krb5_recvauth() routine which may
be triggered by a remote unauthenticated attacker. Fedora Core 3
contains checks within glibc that detect double-free flaws. Therefore,
on Fedora Core 3, successful exploitation of this issue can only lead
to a denial of service (KDC crash). The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-1689 to this issue.

Daniel Wachdorf discovered a single byte heap overflow in the
krb5_unparse_name() function, part of krb5-libs. Successful
exploitation of this flaw would lead to a denial of service (crash).
To trigger this flaw remotely, an attacker would need to have control
of a kerberos realm that shares a cross-realm key with the target,
making exploitation of this flaw unlikely. (CVE-2005-1175).

Daniel Wachdorf also discovered that in error conditions that may
occur in response to correctly-formatted client requests, the Kerberos
5 KDC may attempt to free uninitialized memory. This could allow a
remote attacker to cause a denial of service (KDC crash)
(CVE-2005-1174).

Gaël Delalleau discovered an information disclosure issue in the way
some telnet clients handle messages from a server. An attacker could
construct a malicious telnet server that collects information from the
environment of any victim who connects to it using the Kerberos-aware
telnet client (CVE-2005-0488).

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses the Kerberos-aware
rcp to copy files from a malicious server (CVE-2004-0175).


Solution : http://www.fedoranews.org/blog/index.php?p=753
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb5 package";
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
if ( rpm_check( reference:"krb5-devel-1.3.6-7", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.6-7", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.6-7", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.6-7", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-debuginfo-1.3.6-7", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"krb5-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
 set_kb_item(name:"CVE-2005-1174", value:TRUE);
 set_kb_item(name:"CVE-2005-1175", value:TRUE);
 set_kb_item(name:"CVE-2005-1689", value:TRUE);
}
