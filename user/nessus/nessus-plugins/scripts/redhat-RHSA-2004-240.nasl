#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12503);
 script_bugtraq_id(10397);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521");
 name["english"] = "RHSA-2004-240: SquirrelMail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of the SquirrelMail package installed.

SquirrelMail is a webmail package written in PHP. There is a SQL injection
condition in the remote version of this software which may allow an
attacker to execute arbitrary SQL statements on the database in use.

Solution : https://rhn.redhat.com/errata/RHSA-2004-240.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the SquirrelMail package";
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

if ( rpm_check(release:"RHEL3", prefix:"squirrelmail-", reference:"squirrelmail-1.4.3-0.e3.1", yank:"e") ) security_hole(0);

