#
# (C) Tenable Network Security
#
	

if(description)
{
 script_id(15562);
 script_cve_id("CVE-2004-1634", "CVE-2004-1635");
 script_bugtraq_id(11511);
 script_version ("$Revision: 1.3 $");
 

 name["english"] = "Bugzilla Authentication Bypass and Information Disclosure";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Bugzilla bug tracking system, according to its version
number, is vulnerable to various flaws that may let an attacker bypass
authentication or get access to private bug reports. 

Solution : Upgrade to 2.16.7 or 2.18.0rc3.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-6]|17\..*|18\.0 *rc[0-2]))[^0-9]*$",
       string:version))security_hole(port);
