#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  From: Jedi/Sector One <j@c9x.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow in MySQL
#  Message-ID: <20030910213018.GA5167@c9x.org>
#

if(description)
{
 
 script_id(11842);  
 script_bugtraq_id(8590);
 script_version ("$Revision: 1.11 $");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:281-01");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:042");

 script_cve_id("CVE-2003-0780");
 
 name["english"] = "MySQL password handler overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of MySQL which is 
older than version 4.0.15.

If you have not patched this version, then
any attacker who has the credentials to connect to this
server may execute arbitrary code on this host with
the privileges of the mysql database by changing his
password with a too long one containing a shell code.


Solution : Upgrade to MySQL 3.0.58 or 4.0.15
Risk factor : Medium";

	


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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
if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-7])[^0-9])",
  	  string:ver))security_warning(port);	  
if(ereg(pattern:"^4\.0\.([0-5][^0-9]|1[0-4])", string:ver))security_warning(port);	  
