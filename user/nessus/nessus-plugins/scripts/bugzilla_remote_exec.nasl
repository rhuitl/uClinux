#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Frank van Vliet karin@root66.nl.eu.org
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15565);
 script_bugtraq_id(1199);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2000-0421", "CVE-2001-0329");
 

 name["english"] = "Bugzilla remote arbitrary command execution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Bugzilla bug tracking system, according to its version number, 
is vulnerable to arbitrary commands execution flaws due to a lack of 
sanitization of user-supplied data in process_bug.cgi

Solution : Upgrade at version 2.12 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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


if(ereg(pattern:"(2\.([0-9]|1[01]))[^0-9]*$", string:version))security_hole(port);
       
       
