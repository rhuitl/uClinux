#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#


if(description)
{
  script_id(11134);
  script_version ("$Revision: 1.6 $");
 
  script_name(english:"QMTP");
 
  desc["english"] = "
For your information, a QMTP/QMQP server is running on this port.
QMTP is a proposed replacement of SMTP by D.J. Bernstein.

** Note that Nessus only runs SMTP tests currently.

Risk factor : None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect QMTP servers";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes", "find_service2.nasl");
  script_require_ports(209, 628);

  exit(0);
}

####

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

ports = get_kb_list("Services/QMTP");
if (! ports) ports = make_list(209, 628);
ports = make_list(209, 628);

function netstr(str)
{
  local_var	l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

foreach port (ports)
  if (service_is_unknown(port: port) && get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      msg = strcat(netstr(str: "
Message-ID: <1234567890.666.nessus@example.org>
From: nessus@example.org
To: postmaster@example.com

Nessus is probing this server.
"), 
		netstr(str: "nessus@example.org"),
		netstr(str: netstr(str: "postmaster@example.com")));
      # QMQP encodes the whole message once more
      if (port == 628)
      {
         msg = netstr(str: msg);
         srv = "QMQP";
      }
      else
        srv = "QMTP";

send(socket: soc, data: msg);
r = recv(socket: soc, length: 1024);
close(soc);

if (ereg(pattern: "^[1-9][0-9]*:[KZD]", string: r))
{
  security_note(port);
  register_service(port: port, proto: srv);
}

      if (ereg(pattern: "^[1-9][0-9]*:K", string: r))
      {
        # K: Message accepted for delivery
        # Z: temporary failure
        # D: permanent failure
        if (is_private_addr(addr: get_host_ip()) ||
            is_private_addr(addr: this_host()) )
          security_warning(port: port, data: 
"The " + srv + " server accepts relaying. 
Make sure it rejects connections from Internet so that spammers cannot use
it as an open relay");
        else
          security_hole(port: port, data: 
"The "+ srv + " server accepts relaying on or from Internet. 
Spammers can use it as an open relay.

Risk : High");
      }

    }
  }
