#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21191);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0058");
 
 name["english"] = "Fedora Core 4 2006-194: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-194 (sendmail).

The Sendmail program is a very widely used Mail Transport Agent (MTA).
MTAs send mail from one machine to another. Sendmail is not a client
program, which you use to read your email. Sendmail is a
behind-the-scenes program which actually moves your email over
networks or the Internet to where you want it to go.

If you ever need to reconfigure Sendmail, you will also need to have
the sendmail.cf package installed. If you need documentation on
Sendmail, you can install the sendmail-doc package.

Update Information:

Fixes CVE-2006-0058:

A flaw in the handling of asynchronous signals.
A remote attacker may be able to exploit a race condition to
execute arbitrary code as root.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sendmail-8.13.6-0.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.13.6-0.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-debuginfo-8.13.6-0.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"sendmail-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0058", value:TRUE);
}
