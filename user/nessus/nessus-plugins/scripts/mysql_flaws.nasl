#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 
 script_id(10626);  
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0004");
 script_bugtraq_id(2380, 2522, 926);
 script_cve_id("CVE-2000-0045", "CVE-2001-1275", "CVE-2001-0407");
 script_version ("$Revision: 1.20 $");
 name["english"] = "MySQL various flaws";
 name["francais"] = "MySQL various flaws";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is 
older than version 3.23.36

This version is vulnerable to various flaws
which may allow someone with an access to
this database to execute arbitrary commands as
root or to obtain the password hashes of all the 
database users.
 
Risk factor : High
Solution : Upgrade to version 3.23.36";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver=get_mysql_version(port:port);
if (isnull(ver)) exit(0);
if(ereg(pattern:"^3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-2][0-9])|(3[0-5])))))",
	string:ver))
		security_hole(port);
