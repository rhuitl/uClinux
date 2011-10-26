#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote host is a printer.

Description :

The remote host is a Xerox Document Centre device.

Risk factor :

None";

if (description) {
  script_id(18100);
  script_version("$Revision: 1.5 $");

  name["english"] = "Xerox Document Centre Device Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Xerox Document Centre devices";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "Xerox_MicroServer" >!< banner) exit(0);


# Try to get the Device Profile page (in the Properties tab).
req = http_get(item:"/poDeviceProfile.dhtml", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If this is a Document Centre device...
pat = "<TITLE>(Xerox )?Document Centre ([^<]+)</TITLE>";
if (egrep(string:res, pattern:pat)) {

  # Get the model number from the title; eg,
  #  '<TITLE>Document Centre 220/230</TITLE>'
  #  '<TITLE>Xerox Document Centre 332/340 ST</TITLE>'
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    model = eregmatch(pattern:pat, string:match);
    if (!isnull(model)) {
      model = model[2];
      break;
    }
  }
  if (isnull(model)) model = "unknown";

  # Get the ESS level.
  #
  # nb: the actual level occurs two lines after the label, which will
  #     not always be in English.
  i = 0;
  lines = split(res, keep:FALSE);
  foreach line (lines) {
    if (line =~ "<td width=50%>.+ESS.*:$") {
        ess = lines[i+2];
        break;
    }
    ++i;
  }
  if (isnull(ess)) ess = "unknown";

  # Update KB and report findings.
  set_kb_item(
    name:"www/document_centre",
    value:string(model, ", ESS ", ess)
  );

  desc["english"] += string(
    "\n\nPlugin output:\n\n",
    "  Model:     ", model, "\n",
    "  ESS level: ", ess, "\n"
  );
  security_note(port:port, data:desc);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}
