#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#


if(description)
{
 
 script_id(11378);
 script_bugtraq_id(7052);
 script_cve_id("CVE-2003-0150");
 script_version ("$Revision: 1.7 $");
 name["english"] = "MySQL mysqld Privilege Escalation Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of MySQL which is older than version 3.23.56.
It is vulnerable to a vulnerability that may allow the mysqld service
to start with elevated privileges.

An attacker can exploit this vulnerability by creating a DATADIR/my.cnf
that includes the line 'user=root' under the '[mysqld]' option section.

When the mysqld service is executed, it will run as the root
user instead of the default user. 
 
Risk factor : High
Solution : Upgrade to at least version 3.23.56";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2003 StrongHoldNet");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
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

if(ereg(pattern:"^3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-4][0-9])|(5[0-5])))))",
	string:ver))security_hole(port);
