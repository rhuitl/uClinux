#
# (C) Tenable Network Security
#

if(description)
{
 
 script_id(14831);  
 script_cve_id("CVE-2004-2149");
 script_bugtraq_id(11261);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "MySQL bounded parameter overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL 4.1.x which is older than version 4.1.5.

There is a flaw in the remote version of this software which may allow an attacker
to execute arbitrary commands on the remote host with the privileges of the user
running the mysqld process (typically 'mysql').

See also : http://bugs.mysql.com/bug.php?id=5194
Solution : Upgrade to the latest version of MySQL
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
if(ereg(pattern:"^4\.1\.[0-4][^0-9]", string:ver))security_hole(port);	  
