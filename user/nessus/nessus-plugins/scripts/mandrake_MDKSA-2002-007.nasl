#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:007
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13915);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:007: at";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:007 (at).


zen-parse discovered a problem in the at command containing an extra call to
free() which can lead to a segfault with a carefully crafted, but incorrect,
format. This is caused due to a heap corruption that can be exploited under
certain circumstances because the at command is installed setuid root. Thanks to
SuSE for an additional security improvement that ads the O_EXCL (exclusive)
option to the open(2) system call inside the at code.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:007
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the at package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"at-3.1.8-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
