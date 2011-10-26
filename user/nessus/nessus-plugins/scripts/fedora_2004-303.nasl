#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14789);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11184);
 script_cve_id("CVE-2004-0801");
 
 name["english"] = "Fedora Core 2 2004-303: foomatic";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-303 (foomatic).

Foomatic is a comprehensive, spooler-independent database of printers,
printer drivers, and driver descriptions. It contains utilities to
generate driver description files and printer queues for CUPS, LPD,
LPRng, and PDQ using the database. There is also the possibility to
read the PJL options out of PJL-capable laser printers and take them
into account at the driver description file generation.

There are spooler-independent command line interfaces to manipulate
queues (foomatic-configure) and to print files/manipulate jobs
(foomatic printjob).

The site http://www.linuxprinting.org/ is based on this database.

Update Information:

Sebastian Krahmer reported a bug in the cupsomatic and foomatic-rip print
filters, used by the CUPS print spooler. An attacker who has printing
access could send a carefully named file to the print server causing
arbitrary commands to be executed as root. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0801 to
this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-303.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the foomatic package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"foomatic-3.0.1-3.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-debuginfo-3.0.1-3.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"foomatic-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0801", value:TRUE);
}
