#
# (C) Tenable Network Security
#



if(description)
{
 script_id(11917);
 script_cve_id(
   "CVE-2003-1042",
   "CVE-2003-1043",
   "CVE-2003-1044",
   "CVE-2003-1045",
   "CVE-2003-1046"
 );
 script_bugtraq_id(8953);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Bugzilla SQL flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Bugzilla bug tracking system, according to its version number, is 
vulnerable to various flaws that may let a rogue administrator execute 
arbitrary SQL commands on this host, and which may allow an attacker to
obtain information about bugs marked as being confidential.

Solution : Upgrade to 2.16.4 or 2.17.5.
Risk factor : Medium";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "bugzilla_detect.nasl");
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


if(ereg(pattern:"(1\..*)|(2\.(16\.[0-3]|17\.[0-4]))[^0-9]*$",
       string:version))security_warning(port);
