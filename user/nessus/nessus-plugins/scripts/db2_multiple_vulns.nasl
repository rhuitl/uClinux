#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15486);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(11405, 11404, 11403, 11402, 11401, 11400, 11399, 11398);
 if ( NASL_LEVEL >= 2191 ) script_bugtraq_id(11397, 11396, 11390, 12170, 11327, 11089, 12508, 12509, 12510, 12511, 12512, 12514);
 name["english"] = "DB2 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the IBM DB/2 database. 
There are multiple flaws in the remote version of this software which
may allow an attacker to execute arbitrary commands on the remote host, or
to cause a denial of service against the remote db.

Solution: Upgrade to IBM DB2 V8 + FixPack 7a
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "IBM DB/2 version check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";

 script_family(english:family["english"]);
 script_dependencies("db2_das_detect.nasl");
 script_require_ports("Services/db2das", 523);
 exit(0);
}

#


port = get_kb_item("Services/db2das");
if (!port) port = 523;
if ( !get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
r = recv(socket:soc, length:4096);
if ( ! r ) exit(0);

sql = strstr(r, "SQL0");
if ( ! sql ) exit(0);
if ( ereg(pattern:"^SQL0([0-7][0-9]{3}|80[01][0-9])", string:sql) ) security_hole(port);


