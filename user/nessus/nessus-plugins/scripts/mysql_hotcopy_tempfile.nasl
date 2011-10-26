#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
#  Ref:  Jeroen van Wolffelaar <jeroen@wolffelaar.nl>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14343);
 script_bugtraq_id(10969);
 script_cve_id("CVE-2004-0457");
 script_version ("$Revision: 1.8 $");

 
 name["english"] = "MySQL mysqlhotcopy script insecure temporary file";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is older than version 4.0.21.

mysqlhotcopy is reported to contain an insecure temporary file creation 
vulnerability. 

The result of this is that temporary files created by the application may 
use predictable filenames. 

A local attacker may also possibly exploit this vulnerability to execute 
symbolic link file overwrite attacks. 

*** Note : this vulnerability is local only

Risk factor : Medium
Solution : Upgrade to the latest version of MySQL 4.0.21 or newer";

	


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
if(!port)port = 3306;

ver=get_mysql_version(port:port);
if ((isnull)) exit(0);
if(ereg(pattern:"^3\.|4\.0\.([0-9]|1[0-9]|20)[^0-9]", string:ver))security_warning(port);	  

