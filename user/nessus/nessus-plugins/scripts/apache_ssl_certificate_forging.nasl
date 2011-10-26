#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12046);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0003");
 script_cve_id("CVE-2004-0009");
 script_bugtraq_id(9590);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"3877");
 }
 script_version("$Revision: 1.7 $");
 
 name["english"] = "Apache-SSL Client Certificate Forging Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of ApacheSSL which is older
than 1.3.29/1.53.

This version is vulnerable to a flaw which may allow an attacker to make
the remote server to forge a client certificate.

Solution : Upgrade to version ApacheSSL 1.3.29/1.53 or newer
See also : http://www.apache-ssl.org
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of Apache-SSL";
 summary["francais"] = "Vérifie la version de Apache-SSL";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include ("http_func.inc");
include ("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_backport_banner(banner:get_http_banner(port: port));
 
 serv = strstr(banner, "Server");
 if(ereg(pattern:".*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/1\.([0-9][^0-9]|[0-4][0-9]|5[0-2])[^0-9]", string:serv))
 {
   security_hole(port);
 }
}
