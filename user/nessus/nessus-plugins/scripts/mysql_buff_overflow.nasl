#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
#  Ref: Lukasz Wojtow
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14319);
 script_cve_id("CVE-2004-0836");
 script_bugtraq_id(10981);
 script_version ("$Revision: 1.8 $");

 
 name["english"] = "MySQL buffer overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is older than 4.0.21.

MySQL is a database which runs on both Linux/BSD and Windows platform.
This version is vulnerable to a length overflow within it's 
mysql_real_connect() function.  The overflow is due to an error in the
processing of a return Domain (DNS) record.  An attacker, exploiting
this flaw, would need to control a DNS server which would be queried
by the MySQL server.  A successful attack would give the attacker
the ability to execute arbitrary code on the remote machine.

Risk factor : Medium
Solution : Upgrade to the latest version of MySQL 4.0.21 or newer";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2003 David Maciejak");
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
if(!port)
	port = 3306;

ver=get_mysql_version(port:port);
if(ver==NULL) 
	exit(0);
if(ereg(pattern:"([0-3]\.[0-9]\.[0-9]|4\.0\.([0-9]|1[0-9]|20)[^0-9])", string:ver))security_warning(port);	  

