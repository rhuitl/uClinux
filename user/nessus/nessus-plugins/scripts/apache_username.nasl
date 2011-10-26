#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10766); 
 script_bugtraq_id(3335);
 script_cve_id("CVE-2001-1013");
 script_version ("$Revision: 1.17 $");

 name["english"] = "Apache Remote Username Enumeration Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote Apache server can be used to guess the presence of a given user
name on the remote host.

Description :

When configured with the 'UserDir' option, requests to URLs containing a tilde
followed by a username will redirect the user to a given subdirectory in the
user home.

For instance, by default, requesting /~root/ displays the HTML contents from
/root/public_html/.

If the username requested does not exist, then Apache will reply with a 
different error code. Therefore, an attacker may exploit this vulnerability
to guess the presence of a given user name on the remote host.

Solution : 

In httpd.conf, set the 'UserDir' to 'disabled'.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for the error codes returned by Apache when requesting a non-existant user name";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Teanble Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

#port = get_http_port(default:80);
port = 80;
if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"Server: .*Apache", string:banner) ) exit(0);

req = http_get(item:"/~root", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( ! res ) exit(0);
array = split(res);
code = array[0];
if ( ! code ) exit(0);

req = http_get(item:"/~" + rand_str(length:8), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( ! res ) exit(0);
array = split(res);
code2 = array[0];
if ( ! code2 ) exit(0);

if ( code2 != code ) security_note(port);
