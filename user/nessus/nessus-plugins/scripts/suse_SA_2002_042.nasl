#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:042
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13763);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:042: kdenetwork";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:042 (kdenetwork).


During a security review, the SUSE security team has found two
vulnerabilities in the KDE lanbrowsing service.

LISa is used to identify CIFS and other servers on the local
network, and consists of two main modules: 'lisa', a network daemon,
and 'reslisa', a restricted version of the lisa daemon.  LISa can
be accessed in KDE using the URL type 'lan://', and resLISa using
the URL type 'rlan://'.

LISA will obtain information on the local network by looking for
an existing LISA server on other local hosts, and if there is one,
it retrieves the list of servers from it.  If there is no other LISA
server, it will scan the network itself.

SUSE LINUX can be configured to run the lisa daemon at system boot
time. The daemon is not started by default, however.

The first vulnerability found is a buffer overflow in the lisa
daemon, and can be exploited by an attacker on the local network
to obtain root privilege on a machine running the lisa daemon.
It is not exploitable on a default installation of SUSE LINUX,
because the lisa daemon is not started by default.

The second vulnerability is a buffer overflow in the lan:// URL
handler. It can possibly be exploited by remote attackers to gain
access to the victim user's account, for instance by causing the
user to follow a bad lan:// link in a HTML document.

This update provides fixes for SUSE LINUX 7.2 and 7.3. Previous
updates already corrected the vulnerability in SUSE LINUX 8.0,
and SUSE LINUX 8.1 contains the fix already.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_042_kdenetwork.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdenetwork package";
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
if ( rpm_check( reference:"kdenetwork-2.2.1-101", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-2.1.1-154", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
