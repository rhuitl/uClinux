#TRUSTED afdeaef456f1838a3af17aae122af20fea5530376ff8bf593c3d3915969c860eb5466072d2030dd5db9633db163d480c4051b06a857b5fcaf8efef1a868af98600a815efb4a4023cd415df0ae6297923fa38953ca52d41104583c5aa383180a41a0556672edfe172232676855b3592f40e0f85b33e38a315205354a598610c314c2a825080c4fe187ca7f561eb9b2130e4e140c6422e489a5d57640e42f922aa9ad4756394901073e61c4bdebb4d5953e96bb99c4a2ae23aa99efe85958e684b1f78149376f129aa5d1a4b72658a21a6f9cd80e7f19507a987963369906ca7e2e0f89c64c15fcee4f2ef9301f1c5f1adc6ccdf9b1367162541e4492ee950c275ededfa41c4edb0ad2ae697666fe2402b659d4e9eed2410818c0eb868a3497bebc1de75ac50e584acaa9fc33600e700063312c6976b3f86a3281161aae04a2a69a7540896d6bd26651c9de5c74caa779a18ce77a2508be5fc5f34ea8a7791b91ab708abcb64e9978c421b3ae121764251e2141d677a67c0b093cb4bc4b11ed17615ca93ac8586072d0c5d3c01f7cc6b071f580f7550ce71bccd6dd5e5bd6523bd280c8980776d72600b0f184937669cbce4b36e3ade9a4602776886f68f71493b64b248779d2b4089af14fc5506eb224492e5c6afbc66654b66390146bcb7bf37a862ba0e003c8bc4030c033cbb036bf0e51397ce59657f59290f71866f146e8a
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15885);
 script_version ("1.2");
 name["english"] = "Hydra: SMTP AUTH";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find SMTP AUTH accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force SMTP AUTH authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/smtp", 25);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "find_service_3digits.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/smtp");
if (! port) port = 25;
if (! get_port_state(port)) exit(0);
# NB: Hydra will exit if SMTP AUTH is not enabled

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "smtp-auth";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/smtp-auth/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following SMTP accounts:\n' + report);
