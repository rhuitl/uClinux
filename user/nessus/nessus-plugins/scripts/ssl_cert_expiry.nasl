#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
if ( ! defined_func("localtime") ) exit(0);


# How far (in days) to warn of certificate expiry. [Hmmm, how often
# will scans be run and how quickly can people obtain new certs???]
lookahead = 60;


if (description) {
  script_id(15901);
  script_version ("$Revision: 1.6 $"); 

  script_name(english:"SSL Certificate Expiry");
  script_summary(english:"Checks SSL certificate expiry");

  desc["english"] = "
Synopsis :

The remote server's SSL certificate has already expired or will expire
shortly.

Description :

This script checks expiry dates of certificates associated with
SSL-enabled services on the target and reports whether any have
already expired or will expire shortly.

Solution :

Purchase or generate a new SSL certificate to replace the existing
one. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("find_service.nes");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


# This function converts a date expressed as:
#   Year(2)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var mons, parts, gtime;
  mons = "JanFebMarAprMayJunJulAugSepOctNovDec";

  if (x509time && x509time =~ "^[0-9]{12}Z?$") {
    for (i=0; i<= 6; ++i) {
      parts[i] = substr(x509time, i*2, i*2+1);
    }

    # nb: YY >= 50 => YYYY = 19YY per RFC 3280 (4.1.2.5.1)
    if (ord(parts[0]) >= 50) year = string("19", parts[0]);
    else year = string("20", parts[0]);

    mm = int(parts[1]);
    if (mm >= 1 && mm <= 12) {
      --mm;
      mon = substr(mons, mm*3, mm*3+2);
    }
    else {
      mon = "unk";
    }
    parts[2] = ereg_replace(string:parts[2], pattern:"^0", replace:" ");

    gtime = string(
      mon, " ", 
      parts[2], " ", 
      parts[3], ":", parts[4], ":", parts[5], " ", 
      year, " GMT"
    );
  }
  return gtime;
}


port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);

cert = get_server_cert(port:port, encoding:"der");
if (!isnull(cert)) {

  # nb: maybe someday I'll actually *parse* ASN.1.
  v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
  if (v >= 0) {
    v += 4;
    valid_start = substr(cert, v, v+11);
    v += 15;
    valid_end = substr(cert, v, v+11);

    if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
      # Get dates, expressed in UTC, for checking certs.
      # - right now.
      tm = localtime(unixtime(), utc:TRUE);
      now = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) now += "0"; 
        now += tm[field];
      }
      # - 'lookahead' days in the future.
      tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
      future = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) future += "0"; 
        future += tm[field];
      }
      debug_print("now:    ", now, ".");
      debug_print("future: ", future, ".");

      valid_start_alt = x509time_to_gtime(x509time:valid_start);
      valid_end_alt = x509time_to_gtime(x509time:valid_end);
      debug_print("valid not before: ", valid_start_alt, " (", valid_start, "Z).");
      debug_print("valid not after:  ", valid_end_alt,   " (", valid_end, "Z).");

      if (log_verbosity > 1) debug_print("The SSL certificate on port ", port, " is valid between ", valid_start_alt, " and ", valid_end_alt, ".", level:0);

      if (valid_start > now) {
        security_note(
          data:string("The SSL certificate of the remote service is not valid before ", valid_start_alt, "!"),
          port:port
        );
      }
      else if (valid_end < now) {
        security_warning(
          data:string("The SSL certificate of the remote service expired ", valid_end_alt, "!"),
          port:port
        );
      }
      else if (valid_end < future) {
        security_note(
          data:string("The SSL certificate of the remote service will expire within ", lookahead, " days, at ", valid_end_alt, "."),
          port:port
        );
      }
    }
  }
}
