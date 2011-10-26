#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
#  Ref: Oleksandr Byelkin & Dean Ellis
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(15449);
 script_bugtraq_id(11357);
 script_cve_id("CVE-2004-0835","CVE-2004-0837");

 script_version ("$Revision: 1.6 $");

 
 name["english"] = "MySQL multiple flaws (2)";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running a version of the MySQL database which is
older than 4.0.21 or 3.23.59.

MySQL is a database which runs on both Linux/BSD and Windows platform.
The remote version of this software is vulnerable to specially crafted 
ALTER TABLE SQL query which can be exploited to bypass some applied security 
restrictions or cause a denial of service.

To exploit this flaw, an attacker would need the ability to execute arbitrary
SQL statements on the remote host.

Solution : Upgrade to the latest version of MySQL 3.23.59 or 4.0.21 or newer
Risk factor : Medium";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port) port = 3306;
if ( ! get_port_state(port) ) exit(0);

ver=get_mysql_version(port:port);
if (isnull(ver)) exit(0);
if(ereg(pattern:"^(3\.([0-9]\.|1[0-9]\.|2[0-2]\.|23\.(([0-9]|[1-4][0-9]|5[0-8])[^0-9]))|4\.0\.([0-9]|1[0-9]|20)[^0-9])", string:ver))security_warning(port);	  

