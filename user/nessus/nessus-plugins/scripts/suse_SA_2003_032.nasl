#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13801);
 script_bugtraq_id(8315);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0466");
 
 name["english"] = "SUSE-SA:2003:032: wuftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:032 (wuftpd).


Janusz Niewiadomski and Wojciech Purczynski of iSEC Security Research
have found a single byte buffer overflow in the Washington University
ftp daemon (wuftpd), a widely used ftp server for Linux-like systems.
It is yet unclear if this bug is (remotely) exploitable. Positive
exploitability may result in a remote root compromise of a system
running the wuftpd ftp daemon.

Notes:
* SUSE LINUX products do not contain wuftpd any more starting with SUSE
Linux 8.0 and SUSE LINUX Enterprise Server 8. The wuftpd package has
been substituted by a different server implementation of the file
transfer protocol server.
* The affected wuftpd packages in products as stated in the header of
this announcement actually ship two different wuftpd ftp daemon
versions: The older version 2.4.x that is installed as
/usr/sbin/wu.ftpd, the newer version 2.6 is installed as
/usr/sbin/wu.ftpd-2.6 . The 2.4.x version does not contain the
defective parts of the code and is therefore not vulnerable to the
weakness found.
* If you are using the wuftpd ftp daemon in version 2.4.x, you might
want to update the package anyway in order not to risk an insecure
configuration once you switch to the newer version.

There exists no workaround that can fix this vulnerability on a temporary
basis other than just using the 2.4.x version as mentioned above.
The proper fix for the weakness is to update the package using the
provided update packages.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_032_wuftpd.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wuftpd package";
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
if ( rpm_check( reference:"wuftpd-2.6.0-403", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wuftpd-2.6.0-403", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wuftpd-", release:"SUSE7.2")
 || rpm_exists(rpm:"wuftpd-", release:"SUSE7.3") )
{
 set_kb_item(name:"CVE-2003-0466", value:TRUE);
}
