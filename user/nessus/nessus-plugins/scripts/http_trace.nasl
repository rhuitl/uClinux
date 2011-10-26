#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
#
# HTTP/1.1 is defined by RFC 2068
#
# Check for proxy on the way (transparent or reverse?!)
#

if(description)
{
 script_id(11040);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "HTTP TRACE";
 name["francais"] = "TRACE HTTP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Transparent or reverse HTTP proxies may be implement on some sites.

Risk factor : None";


 desc["francais"] = "
Des proxys HTTP transparent ou 'reverse' sont susceptibles d'être 
installés sur certains sites.

Risque: aucun";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Look for an HTTP proxy on the way";
 summary["francais"] = "Cherche un proxy HTTP sur le chemin";
 
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "General";
 script_family(english:family["english"]);
 # script_dependencie("find_service.nes", "httpver.nasl");
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

req = http_get(port: port, item: "/");
send(socket: soc, data: req);
heads = http_recv_headers2(socket:soc);
via = egrep(pattern: "^Via: ", string: heads);
trace="";
if (via)
{
  # display(via);
  via=ereg_replace(string: via, pattern: "^Via: *", replace:"");
  via=via-string("\r\n");
  while(via)
  {
    # display("Via=", via, "\n");
    proxy = ereg_replace(string:via, pattern: " *([^,]*),?.*", replace: "\1");
    via = ereg_replace(string: via, pattern: "([^,]*)(, *)?(.*)", replace: "\3");
    # display(string("Proxy=", proxy, " - Via=", via, "\n"));
    proto = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) +.*",
		replace: "\1");
    line = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) *(.*)",
		replace: "\2");
    # display(string("Proto=", proto, "\nLine=", line, "\n"));
    if (egrep(pattern:"^[0-9]+", string: proto))
      proto = "HTTP/" + proto;
    trace = trace + proto;
    l = strlen(proto);
    for (i= l;i < 12; i=i+1) trace=trace+" ";
    trace=string(trace, " ", line, "\n");
  }
}

close(soc);

if (trace)
  security_note(port: port, data: string("The GET method revealed those proxies on the way to this web server :\n", trace));
else if (egrep(pattern: "^X-Cache:", string: heads))
{
  p = ereg_replace(pattern:'^X-Cache: *[A-Z]+ +from +([^ \t\r\n]+)[ \t\r\n]+',
	string: heads, replace: "\1");
  r = 'There might be a caching proxy on the way to this web server';
  if (p != heads) r = strcat(r, ':\n', p);
  security_note(port: port, data: r);
}

exit(0); # broken at this time
#
ver=get_kb_item(string("http/", port));
if ((ver == "10") || (ver == "09")) exit(0);	# No TRACE in HTTP/1.0

n=0;
for (i=0; i<99;i=i+1)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    req=string("TRACE / HTTP/1.1\r\nHost: ", get_host_name(), 
	"\r\nUser-Agent: Nessus\r\nMax-Forwards: ", i,
	"\r\n\r\n");

    send(socket: soc, data: req);
    buf = http_recv_headers2(socket:soc);
    #
    via = egrep(pattern: "^Via: ", string: buf);
    if (via)
    {
      via = ereg_replace(string: via, pattern: "^Via: *", replace:"");
      viaL[i] = via - string("\r\n");
# display(string("V[", i, "]=", viaL[i], "\n"));
    }
    else
      viaL[i] = string("?");
    #
    if (egrep(string: buf, pattern: "^HTTP/.* 200 "))
    {
      buf2 = recv_line(socket: soc, length: 2048);
      # The proxy is supposed to send back the request it got. 
      # i.e. "TRACE / HTTP/1.1"
      # However, NetCache appliance change it to "TRACE http://srv HTTP/1.1"
      if (egrep(pattern: "^TRACE (/|http://.*) HTTP/1.1", string: buf2))
      {
        srv = egrep(pattern: "^Server: ", string: buf);
        if (srv)
        {
          srv = ereg_replace(string: srv, pattern: "^Server: *", replace:"");
          srvL[i+1] = srv - string("\r\n");
# display(string("S[", i+1, "]=", srvL[i+1], "\n"));
        }
        else
          srvL[i+1] = string("?");
        n=n+1;
      }
    }
    else
      i=9999;
#
    close(soc);
  }
  else
    i = 9999;
}
  
trace="";
for (i = 1; i <= n; i = i+1)
{
  trace=string(trace, viaL[i]," - ", srvL[i], "\n");
}

if (n > 0)
  security_note(port:port, protocol:"tcp",
	data:string("The TRACE method revealed ", n, 
	" proxy(s) between us and the web server :\n",
	trace,"\nRisk factor : None"));
