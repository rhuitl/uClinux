#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote host is running a web server for Samba administration.

Description :

The remote host is running SWAT, the Samba Web Administration Tool.

SWAT is a web-based configuration tool for Samba administration that
also allows for network-wide MS Windows network password management. 

See also :

http://www.samba.org/samba/docs/man/Samba-HOWTO-Collection/SWAT.html

Solution :

Either disable SWAT or limit access to authorized users and ensure that
it is set up with stunnel to encrypt network traffic. 

Risk factor : 

None";


if (description) {
  script_id(10273);
  script_version("$Revision: 1.19 $");

  name["english"] = "SWAT Detection";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);
 
  summary["english"] = "Detects a SWAT Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/swat", "Services/www", 901);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


# Fire on any ports that find_services already identified as running SWAT.
port901 = 0;
foreach port (get_kb_list("Services/swat")) {
  if (port == 901) port901 = 1;
  if (get_port_state(port)) {
    security_note(port);
  }
}


# Explicitly test various ports.
if (thorough_tests) {
  if (port901) ports = get_kb_list("Services/www");
  else ports = add_port_in_list(list:get_kb_list("Services/www"), port:901);
}
else {
  if (port901) ports = make_list();
  else ports = make_list(901);
}
if (! isnull(ports)) {
  foreach port (ports) {
    if ( ! get_port_state(port) ) continue;
    # Try to pull up the initial page.
    req = http_get(item:"/", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # SWAT's running if we're prompted to authenticated to the SWAT realm.
    if ('WWW-Authenticate: Basic realm="SWAT"' >< res) {
      security_note(port);
    }
    # else SWAT's running in demo mode if we get to the initial page.
    else if (
      '<TITLE>Samba Web Administration Tool</TITLE>' >< res &&
      '<IMG SRC="/swat/images/samba.gif" ALT="[ Samba ]" border=0>' >< res
    ) {
      desc = str_replace(
        string:desc["english"],
        find:"See also :",
        replace:string(
          "***** The remote SWAT server appears to be running in demo mode.\n",
          "***** In demo mode, authentication is disabled and anyone can\n",
          "***** use SWAT to modify Samba's configuration file. Demo mode\n",
          "***** should not be used on a production server.\n",
          "\n",
          "See also :"
        )
      );
      security_warning(port:port, data:desc);
    }
  }
}
