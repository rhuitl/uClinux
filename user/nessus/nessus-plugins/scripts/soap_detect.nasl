#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

There is a SOAP server listening on the remote host. 

Description :

The remote host is running a SOAP server.  SOAP, originally an acronym
for 'Simple Object Access Protocol', is an XML-based distributed
messaging protocol typically implemented over HTTP. 

See also :

http://en.wikipedia.org/wiki/SOAP
http://www.w3.org/TR/soap12-part0/

Solution :

Limit incoming traffic to this port if desired. 

Risk factor :

None";


if (description)
{
  script_id(22477);
  script_version("$Revision: 1.1 $");

  script_name(english:"SOAP Server Detection");
  script_summary(english:"Detects a SOAP Server");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


if (!thorough_tests) exit(0);
port = get_unknown_svc(0);             # nb: no default
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Send a simple SOAP method request.
urn = "example-com:nessus";
method = "getPluginResults";

postdata = strcat(
  "<?xml version='1.0' ?>", '\n',
  '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
  "<soap:Body>", '\n',
  '   <i:', method, ' xmlns:i="', urn, '">\n',
  '     <pluginName>', SCRIPT_NAME, '</pluginName>\n',
  '   </i:', method, '>\n',
  ' </soap:Body>\n',
  '</soap:Envelope>'
);
req = string(
  "POST / HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "SOAPMethodName: urn:", urn, "#", method, "\r\n",
  "Content-Type: text/xml\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# It's a SOAP server if we see an error involving our URN.
if (string("java.lang.ClassNotFoundException: Failed to locate SOAP processor: ", urn) >< res)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"soap_http");

  security_note(port);
}
