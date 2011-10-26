#
# (C) Tenable Network Security
#


if (description) {
  script_id(20386);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-3357");
  script_bugtraq_id(16152);

  script_name(english:"Apache mod_ssl Error Document Denial of Service Vulnerability");
  script_summary(english:"Checks for error document denial of service vulnerability in Apache mod_ssl");

  desc = "
Synopsis :

The remote web server is affected by a denial of service flaw. 

Description :

The installed version of Apache with mod_ssl on the remote host
appears susceptible to a remote denial of service flaw under certain
atypical configurations.  A remote attacker may be able to exploit
this issue to crash individual child processes or even the entire
server, thereby denying service to legitimate users. 

See also :

http://issues.apache.org/bugzilla/show_bug.cgi?id=37791

Solution : 

Update the Apache configuration to use ''SSLRequire' whenever
'SSLCipherSuite' is used. 

Risk factor : 

Low / CVSS Base Score : 2.6
(AV:R/AC:H/Au:NR/C:N/I:N/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}


include("http_func.inc");
include("global_settings.inc");


port = get_http_port(default:443);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if ( report_paranoia <= 1 )
{
 if (! banner || "Apache" >!< banner ) exit(0);
 if ( "mod_ssl" >!< banner ) exit(0);
}


# If it's using SSL....
encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps >= 2) {
  req = http_get(item:"/", port:port);

  # Try several times to connect w/o SSL.
  tries = 5;
  for (iter = 0; iter < tries; iter++) {
    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if (soc) {
      send(socket:soc, data:req);
      res = http_recv(socket:soc);
      close(soc);

      # It's *not* a problem if we got a response.
      if (res) exit(0);
    }
  }

  # There's a problem since we didn't get a response after several attempts.
  #
  # nb: this exploit won't crash the entire web server unless the remote
  #     Apache is configured to use the non-default worker MPM.
  security_note(port);
}
