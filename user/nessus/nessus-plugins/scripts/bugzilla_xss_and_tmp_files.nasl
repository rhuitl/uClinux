#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# Date: Fri, 25 Apr 2003 04:40:33 -0400
# To: bugtraq@securityfocus.com, announce@bugzilla.org,
# From: David Miller <justdave@syndicomm.com>
# Subject: [BUGZILLA] Security Advisory - XSS, insecure temporary filenames
	



if(description)
{
 script_id(11553);
 script_bugtraq_id(7412);
 script_cve_id("CVE-2003-0603");
 script_version ("$Revision: 1.8 $");
 

 name["english"] = "Bugzilla XSS and insecure temporary filenames";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains a CGI which is vulnerable to a cross site scripting
and file deletion vulnerability

Description : 

The remote Bugzilla bug tracking system, according to its version number, is 
vulnerable to various flaws that may let an attacker perform cross site 
scripting attacks or even delete local file files (provided he has an account
on the remote host).

Solution : 

Upgrade to 2.16.3 or 2.17.4

Risk factor : 
Low / CVSS Base Score : 3
(AV:R/AC:L/Au:R/C:N/A:N/I:C/B:I)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-2]|17\.[0-3]))[^0-9]*$",
       string:version)){
		 security_note(port);
	}
       
