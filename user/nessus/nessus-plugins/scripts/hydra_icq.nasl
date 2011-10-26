#TRUSTED 9757f9be3e80b37f2d6cfee44e7c5e0b844e4b9c0b2470a5311a38c75dcfae30e58437a651b92f5ae23a46c789f32f4ed09cab878b161ccd6532542476bc36468371ffeac30bfa59232ea6cc5df6c8639079a28bc28b0f3306fd8c6b393420ba7863b38efb8561dddcd2b24f316a95c2d9a3af4efcd80d84c53f9b3c31224e95695240ea519cb3d3ccf087b416b1c202b155c8fcd39ce758d2700cf968afaaa840938ed080734583885d6f0ed21e15a7ff16fc597a833ec96cdec2db3e88b7d10bec6a4dcaf898811a03f4e42bc4b5928bd656cfa9bffc389fbc27411aff9d4c027c244732103b822937fa5ded2bbfa59638cec07f858e19e5002faa37535f6631079b6e081baf6541e36cac806152f92dd2037df1210d920ed3ff91c3318e14c52b13b20145f1d6a912df27abb5589248789ba641f85b4456827fd8700690064e92d34d370512f05a28a38ebbd0f22309332c051c1645c08d795ee7e9c225d631713703de2076975e9df29916c9431983bfb081bf7eafa3d6a58cb2cbb22427449507fbd9799e2e111de3ad58c9a0e0f5258cfb193163429180a7b82be13dce0ebbecd36438fcb6ecb9f1f1692463cb98cbee19a034121e218a263d050416839a64e626da0a00b371d372ca4093738f56d2e7b4f801f5e9dfd4497f45434cb5ea54a8d102d03d2ca92bfb745751d7ceac5e45194915545c805cd837f814293a
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15875);
 script_version ("1.2");
 name["english"] = "Hydra: ICQ";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find ICQ accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force ICQ authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/icq", 5190);
 script_dependencies("hydra_options.nasl", "find_service.nes");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/icq");
if (! port) port = 5190;
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
argv[i++] = "icq";

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
    set_kb_item(name: 'Hydra/icq/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following ICQ accounts:\n' + report);
