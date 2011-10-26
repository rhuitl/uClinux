# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL

if(description)
{
 script_id(18366);
 script_version ("$Revision: 1.2 $");

 script_name(english: "Several GET locks web server");
 
 desc = "
The remote web server shuts down temporarily or blacklists
us when it receives several GET HTTP/1.0 requests in a row.

This might trigger false positive in generic destructive 
or DoS plugins.
** Nessus enabled some countermeasures, however they might be 
** insufficient. 

Risk factor : None";

 script_description(english:desc);

 script_summary(english: "Several GET requests in a row temporarily shut down the web server");
 # It is not really destructive, but it is useless in safe_checks mode
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Misc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include('global_settings.inc');
include('http_func.inc');

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

# CISCO IP Phone 7940 behaves correctly on a HTTP/1.1 request,
# so we forge a crude HTTP/1.0 request. 
# r = http_get(port: port, item: '/'); 
r = 'GET / HTTP/1.0\r\n\r\n';
max = 12;

for (i = 0; i < max; i ++) 
{
 soc = http_open_socket(port);
 if (! soc) break;
 send(socket: soc, data: r);
 recv(socket: soc, length: 8192);
 http_close_socket(soc);
}

debug_print('i=', i, '\n');
if (i == 0)
 debug_print('Server is dead?');
else if (i < max)
{
 debug_print('Web server rejected connections after ', i, ' connections\n');
 set_kb_item(name: 'www/multiple_get/'+port, value: i);
 if (report_verbosity > 1)	# Verbose report
  security_note(port);
}


