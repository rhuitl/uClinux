#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.00 (last update 23.11.01)
#
# Changes by rd: re-wrote the code to do pattern matching

if(description)
{
 script_id(10803);
 script_cve_id("CVE-2001-0868");
 script_bugtraq_id(3577);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Redhat Stronghold File System Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
Redhat Stronghold Secure Server File System Disclosure Vulnerability

The problem:
In Redhat Stronghold from versions 2.3 up to 3.0 a flaw exists that
allows a remote attacker to disclose sensitive system files including
the httpd.conf file, if a restricted access to the server status
report is not enabled when using those features.
This may assist an attacker in performing further attacks.

By trying the following urls, an attacker can gather sensitive
information:
http://target/stronghold-info will give information on configuration
http://target/stronghold-status will return among other information
the list of request made

Please note that this attack can be performed after a default
installation. The vulnerability seems to affect all previous version
of Stronghold.

Vendor status:
Patch was released (November 19, 2001)

Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Redhat Stronghold File System Disclosure";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie( "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 req = http_get(item:"/stronghold-info", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if (! r ) exit(0);
 if("Stronghold Server Information" >< r)
 {
   security_warning(port);
   exit(0);
 }

  req = http_get(item:"/stronghold-status", port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if("Stronghold Server Status for" >< r)security_warning(port);
}
