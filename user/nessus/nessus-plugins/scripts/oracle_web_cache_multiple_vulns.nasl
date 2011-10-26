#
# (C) Tenable Network Security
#





if(description)
{
 script_id(12126);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0011");
 script_bugtraq_id(9868);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0385");
 name["english"] = "Oracle AS Web Cache Multiple vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Oracle Application Server Web Cache
version 9.0.4.0 or older.

There is a heap overflow condition in this version of the software, which
may allow an attacker to execute arbitrary code on this host.

Solution : http://otn.oracle.com/deploy/security/pdf/2004alert66.pdf
See also : http://www.inaccessnetworks.com/ian/services/secadv01.txt
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Oracle AS WebCache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


banner = get_http_banner(port: port);
if(!banner)exit(0);

# Oracle AS10g/9.0.4 Oracle HTTP Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/(9\.0\.[0-3]\.[0-9]|2\..*)", string:banner))
{
   security_hole(port);
   exit(0);
}

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/9\.0\.4\.0", string:banner))
{
  os = get_kb_item("Host/OS/icmp");
  if ( !os || ("Windows" >!< os && "Tru64" >!< os && "AIX" >!< os)) security_hole ( port );
}
