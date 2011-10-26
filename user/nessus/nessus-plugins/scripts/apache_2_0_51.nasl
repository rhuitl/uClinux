#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14748);
 script_bugtraq_id(11185, 11187);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0032");
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0786", "CVE-2004-0747", "CVE-2004-0751", "CVE-2004-0748", "CVE-2004-0809");
 name["english"] = "Apache < 2.0.51";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Apache2 which is older than 2.0.51.

It is reported that versions prior 2.0.51 are prone to a remote denial of 
service issue. An attacker may issue a specific sequence of DAV LOCK commands 
to crash the process. If Apache is configured to use threads, it may 
completely crash the Apache process.

In addition to this, versions prior 2.0.51 are prone to a remote buffer 
overflow when parsing an URI sent over IPv6. An attacker may use this flaw 
to execute arbitrary code on the remote host or to deny service to legitimate 
users.

See also : http://issues.apache.org/bugzilla/show_bug.cgi?id=31183
Solution : Upgrade to Apache 2.0.51
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-4][0-9]|50)[^0-9]", string:serv))
 {
   security_hole(port);
 }
