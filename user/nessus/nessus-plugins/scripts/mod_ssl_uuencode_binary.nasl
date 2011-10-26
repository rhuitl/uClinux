#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(12255);
 script_bugtraq_id(10355);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0488");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"6472");

 
 name["english"] = "mod_ssl SSL_Util_UUEncode_Binary Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of mod_ssl which is
older than 2.8.18.

This version is vulnerable to a flaw which may allow an attacker to disable 
the remote web site remotely, or to execute arbitrary code on the remote
host.

*** Note that several Linux distributions patched the old version of 
*** this module. Therefore, this alert might be a false positive. Please 
*** check with your vendor to determine if you really are vulnerable to 
*** this flaw

Solution : Upgrade to version 2.8.18 (Apache 1.3) or to Apache 2.0.50
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of mod_ssl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "redhat-RHSA-2004-245.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);
if ( get_kb_item("CVE-2004-0488") ) exit(0);


banner = get_backport_banner(banner:get_http_banner(port:port));
if(!banner)exit(0);

if ( "Darwin" >< banner )  exit(0);
 
serv = strstr(banner, "Server");

if(ereg(pattern:"Apache/1\..*mod_ssl/(1\.|2\.([0-7]\.|8\.([0-9][^0-9]|1[0-7]))).*", string:serv))
{
   security_hole(port);
}
if(ereg(pattern:"Apache/2\..*mod_ssl/(1\.|2\.0\.([0-9][^0-9]|[0-4][0-9][^0-9]))", string:serv))
{
   security_hole(port);
}
