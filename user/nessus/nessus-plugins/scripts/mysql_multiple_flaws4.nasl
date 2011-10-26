#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17313);  
 script_bugtraq_id(12781);
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "MySQL multiple flaws (4)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running a version of MySQL which older than version
4.0.24 or 4.1.10a

There are several flaws in the remote version of this database server
which may allow an authenticated attacker to execute arbitrary code on
the remote host.

Solution : Upgrade to MySQL 4.0.24 or 4.1.10a
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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
if(ereg(pattern:"^([0-3]\.|4\.0\.([0-9]|1[0-9]|2[0-3])([^0-9]|$)|4\.1\.[0-9][^0-9])", string:ver))security_warning(port);	
