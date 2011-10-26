#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://www.mysql.com/doc/en/News-3.23.55.html
# 
#

if(description)
{
 script_id(11299);  
 script_bugtraq_id(6718);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0073", "CVE-2003-0150");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:093-01");

 
 name["english"] = "MySQL double free()";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is 
older than version 3.23.55.

If you have not patched this version, then
any attacker with a valid username may crash this 
service remotely by exploiting a double free bug.

Further exploitation to gain a shell on the host 
might be possible, although unconfirmed so far.

Risk factor : Medium
Solution : Upgrade to the latest version of MySQL 3.23.55 or newer";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-4])[^0-9])", string:ver))security_warning(port);	  

