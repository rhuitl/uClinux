#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18439);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1267");
 
 name["english"] = "Fedora Core 3 2005-406: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-406 (tcpdump).

Tcpdump is a command-line tool for monitoring network traffic.
Tcpdump can capture and display the packet headers on a particular
network interface or on all interfaces. Tcpdump can display all of
the packet headers, or just the ones that match particular criteria.

Install tcpdump if you need a program to monitor network traffic.


* Tue Jun 07 2005 Martin Stransky - 14:3.8.2-9.FC3

- fix for CVE-2005-1267 - BGP DoS, #159209



Solution : http://www.fedoranews.org/blog/index.php?p=716
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"tcpdump-3.8.2-9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.8.3-9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"arpwatch-2.1a13-9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-debuginfo-3.8.2-9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"tcpdump-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1267", value:TRUE);
}
