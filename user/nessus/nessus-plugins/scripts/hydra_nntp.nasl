#TRUSTED 2eb1885650a738eec012bed8dd2a097978ac1e7617c3f2a3a9d7b29a9708a38d3d1dc36f337910b5c7d87fd2504f59c556be9f19718c059234e7b5d9f2067e8b02e171fc09c11d5be9c7651375e7e840ae4dbc1b915e7a8f1987d11c6ec8bd5144ab3f5e8338816c54d1df1b582cd247f78e0d4f7a81495d62fe9a05a5f7314c95a782ceef6ca9ca67b07339f23b048fb243ca0aa033b53029e924c420bc7e4235c61300cf581deaee4f4d8599b2059f295297c54110d852a8db7f6cfed12eb5d2ab0d1ecdfd8b48cb491bc06527d89c04025b0d7dd482fd7d09fda4d70f8e94b1cfca2d287f15c61e7d72a5910c6588fe2f278ac5415b7eb1e95e2f44f838d36b629e3c2079c71bf0fe90ae90abf331c549f6f7d0061d53d53219ffaf1d40b8768d671d9450ef7ebb9d8f8c506e33de35f8e71d6f75705c6851fd7c23e2cd1dd3bb857e608b9f3fdf99dd598e9c60aab533f72f856b7d7ef038f7429b7373edd16fbf78d3d4657c1a65ef6b3e6c850749f73413e89aa852a955032c1608060ea09195d9d203c287934269b7e48ef7b89c526c5819bc9dd90c2e72c86b289a76c07304bc632380cf81f1748bf5cba0b650d9cf24a9ab8f20c349798dcb53f4f10b97aca500897b4f36776733cab945ec0143ef34924427a8f7e6bfdde922ac0ff40a106dd3f54e6ea934e86351f5a87b04d5066a7e08d36e3584cacbf28df20f
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

# No use to run this one if the other plugins cannot run!
if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15879);
 script_version ("1.2");
 name["english"] = "Hydra: NNTP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find NNTP accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force NNTP authentication with Hydra";
 script_summary(english:summary["english"]);
 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/nntp", 119);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "find_service_3digits.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/nntp");
if (! port) port = 119;
if (! get_port_state(port)) exit(0);

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
argv[i++] = "nntp";

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
    set_kb_item(name: 'Hydra/nntp/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following NNTP accounts:\n' + report);
