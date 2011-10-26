#
# Check for bad permissions on a web server
#
# RFCs:
# 1945 Hypertext Transfer Protocol -- HTTP/1.0. T. Berners-Lee, R.
#      Fielding, H. Frystyk. May 1996. (Format: TXT=137582 bytes) (Status:
#      INFORMATIONAL)
# 2068 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, T. Berners-Lee. January 1997. (Format:
#      TXT=378114 bytes) (Obsoleted by RFC2616) (Status: PROPOSED STANDARD)
# 2616 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, L. Masinter, P. Leach, T. Berners-Lee. June
#      1999. (Format: TXT=422317, PS=5529857, PDF=550558 bytes) (Obsoletes
#      RFC2068) (Updated by RFC2817) (Status: DRAFT STANDARD)
#

if(description)
{
 script_id(10498);
 script_version ("$Revision: 1.31 $");
 script_bugtraq_id(12141);
 if (defined_func("script_xref"))
  script_xref(name:"OWASP", value:"OWASP-CM-001");
 
 name["english"] = "Test HTTP dangerous methods";
 name["francais"] = "Teste les méthodes HTTP dangereuses";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Misconfigured web servers allows remote clients to perform
dangerous HTTP methods such as PUT and DELETE. This script
checks if they are enabled and can be run

Risk factor : Medium";


 desc["francais"] = "
Certains serveurs web mal configurés permettent aux clients
d'effectuer les méthodes DELETE et PUT. Ce script vérifie
si elles sont activées et si elles peuvent être lancées";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Verifies the access rights to the web server (PUT, DELETE)";
 summary["francais"] = "Vérifie les droits d'accès au serveur web (PUT, DELETE)";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 # Integrist check verifies if the PUT and DELETE methods are _disabled_
 # i.e. the web server should return a 501 error instead of 403
 # With IIS, there is no way to get a 5xx error code.
 #script_add_preference(name:"Integrist test", type:"checkbox", value:"no");

 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Michel Arboi",
		francais:"Ce script est Copyright (C) 2000 Michel Arboi");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

#integrist = script_get_preference("Integrist test");
#if (!integrist) integrist="no";

function exists(file, port)
{
 local_var	_soc, req, r, buf;

 _soc = http_open_socket(port);
 if(!_soc)return(0);
 req = http_get(item:file, port:port);
 send(socket:_soc, data:req);
 r = recv_line(socket:_soc, length:4096);
 buf = http_recv(socket: _soc, code: r);
 close(_soc);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:r)
    && ("A quick brown fox jumps over the lazy dog" >< buf))
 {
   return(1);
 }
 else
  return(0);
}


port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

# look for Allow field
req = http_get(item: "*", port: port);
req = str_replace(string: req, find: "GET", replace: "OPTIONS", count: 1);
send(socket: soc, data: req);
r = http_recv(socket: soc);

allow = egrep(string: r, pattern: "^Allow:");
##if (!allow) allow = "Allow: PUT,DELETE";

soc = http_open_socket(port);
if (!soc) exit(0);

 for (i=1; exists(file:string("/puttest", i,".html"), port:port); i = i+1)
 {
   if(i > 20)exit(0); # we could not test this server - really strange
 } 
 name = string("/puttest",i,".html");
 #display(name, " is not installed\n");
 c = crap(length:77, data:"A quick brown fox jumps over the lazy dog");
 req = http_put(item:name, port:port, data:c);
 send(socket:soc, data:req);

 l = recv_line(socket:soc,length:1024);
 close(soc);
 #display(l);
 upload=0;
 if (exists(port:port, file:name)) {
  upload=1;
  security_warning(port:port, protocol:"tcp",
data: string("We could upload the file '",name, "' onto your web server\nThis allows an attacker to run arbitrary code on your server, or set a trojan horse\nSolution : disable this method\nRisk factor : High") );
 } else {
   #if("yes" >< integrist)
    {
  if (" 401 " >< l && "PUT" >< allow) {
   #display("answer = ", l, "\n");
   security_warning(port:port, protocol:"tcp",
data:string("It seems that the PUT method is enabled on your web server\nAlthough we could not exploit this, you'd better disable it\nSolution : disable this method\nRisk factor : Medium"));
    }
  }
 }

 
 # Leave file for next test (DELETE). Dirty...

 if (! upload) { name = NULL; }


 
if (name)
{ 
 soc = http_open_socket(port);
 if(!soc)exit(0);
 req = http_delete(item:name, port:port);
 send(socket:soc, data: req);
 l = recv_line(socket:soc, length:1024);

 if (" 200 " >< l) {
  e = exists(port:port, file:name);
}
else
 e = 1;

  if(!e)
    security_hole(port:port, protocol:"tcp",
data: string("We could DELETE the file '", name, "'on your web server\nThis allows an attacker to destroy some of your pages\nSolution : disable this method\nRisk factor : High") ) ;
 } else {
  if (" 401 " >< l && " is disabled " >!< l && "DELETE" >< allow) {
   security_warning(port:port, protocol:"tcp",
data:string("It seems that the DELETE method is enabled on your web server\nAlthough we could not exploit this, you'd better disable it\nSolution : disable this method\nRisk factor : Medium"));
 }
}
 
