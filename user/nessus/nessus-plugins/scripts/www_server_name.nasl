#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################

if(description)
{
 script_id(11239);
 script_version ("$Revision: 1.10 $");
 #script_bugtraq_id(2979);
 #script_cve_id("CVE-2000-0002");
 
 name["english"] = "Hidden WWW server name";
 script_name(english:name["english"]);
 
 desc["english"] = "
It seems that your web server tries to hide its version 
or name, which is a good thing.
However, using a special crafted request, Nessus was able 
to discover it.

Risk factor : None

Solution : Fix your configuration.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tries to discover the web server name";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", "httpver.nasl", 80);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if (  get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


s = http_open_socket(port);
if(! s) exit(0);

r = http_get(port: port, item: "/");
send(socket: s, data: r);

r = http_recv_headers2(socket:s);
http_close_socket(s);

# If anybody can get the server name, exit
srv = string("^Server: *[^ \t\n\r]");
if (egrep(string: r, pattern: srv)) exit(0);

i = 0;
req[i] = string("HELP\r\n\r\n"); i=i+1;
req[i] = string("HEAD / \r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.0\r\n\r\n"); i=i+1;
req[i] = string("HEAD / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n"); i=i+1;

for (i = 0; req[i]; i=i+1)
{
  s = http_open_socket(port);
  if (s)
  {
    send(socket: s, data: req[i]);
    r = http_recv_headers2(socket:s);
    http_close_socket(s);
    if (strlen(r) && (s1 = egrep(string: r, pattern: srv)))
    {
     s1 -= '\r\n'; s1 -= 'Server:';
     rep = "
It seems that your web server tries to hide its version 
or name, which is a good thing.
However, using a special crafted request, Nessus was able 
to determine that is is running : 
" + s1 + "

Risk factor : None
Solution : Fix your configuration.";

      security_warning(port:port, data:rep);
      # We check before: creating a list is not a good idea
      sb = string("www/banner/", port);
      if (! get_kb_item(sb))
	{
	 if ( defined_func("replace_kb_item") )
        	replace_kb_item(name: sb, value: r);
	  else
        	set_kb_item(name: sb, value: r);
	}
      else
      {
        sb = string("www/alt-banner/", port);
        if (! get_kb_item(sb))
          set_kb_item(name: sb, value: r);
      }
      exit(0);
    }
  }
}
