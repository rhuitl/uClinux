/*
 * voice_default.h
 *
 * This file contains the default values for vgetty, vm and the pvf
 * tools. All of these values can be changed by the configuration
 * file.
 *
 * $Id: default.h,v 1.9 2005/03/13 17:27:42 gert Exp $
 *
 */

/*
 * Keywords
 * --------
 */

KEYWORD(part)
KEYWORD(program)
KEYWORD(port)
KEYWORD(ring_type)

/*
 * Common defaults
 * ---------------
 */

/*
 * Default log level for the voice programs.
 */

CONF(voice_log_level, L_MESG, CT_INT)

/* Default shell log file */

CONF(voice_shell_log, STRING "", CT_STRING)

/*
 * Default shell to invoke for shell scripts. The default is "/bin/sh"
 */

CONF(voice_shell, STRING "/bin/sh", CT_STRING)

/*
 * Default port speed. The bps rate must be high enough for the compression
 * mode used. Note that this is an integer, not one of the Bxxxx defines. 
 * This must be set to 38400 for some old Rockell modems. The default value
 * is 38400.
 */

CONF(port_speed, 38400, CT_INT)

/*
 * Default port timeout in seconds for a read or write operation. The
 * default value is 10 seconds.
 */

CONF(port_timeout, 10, CT_INT)

/*
 * Default timeout for a dialout in seconds. The default value is 90 seconds.
 */

CONF(dial_timeout, 90, CT_INT)

/*
 * Delay before sending a new voice command to the modem in milliseconds.
 * The default is 100 milliseconds.
 */

CONF(command_delay, 100, CT_INT)

/*
 * Minimum length of detected DTMF tones, in milliseconds. This is
 * currently only supported by ZyXel modems with a ROM release of 6.12
 * or above. The default is 30 milliseconds.
 */

CONF(dtmf_len, 30, CT_INT)

/*
 * DTMF tone detection threshold in percent (0% to 100%). Increase this
 * if the modem erroneously detects DTMF tones, decrease it if it fails to
 * detect real ones. This is currently only supported by ZyXel modems
 * with a ROM release of 6.12 or above. The default is 40%.
 */

CONF(dtmf_threshold, 40, CT_INT)

/*
 * Time to wait for a DTMF tone to arrive when recording or waiting
 * for DTMF input in seconds. The default is to wait for 7 seconds.
 */

CONF(dtmf_wait, 7, CT_INT)

/*
 * In Australia the frequency of the busy signal is the same as the
 * frequency of the fax calling tone. This causes problems on at least
 * some modems. They report a fax calling tone, when there is a busy
 * signal in reality. To help those user, vgetty will ignore any fax
 * calling tone detected by the modem, when this option is set.
 *
 * The following companys suffer from this problem:
 * - Telstra (formerly Telecom Australia)
 * - Optus
 * - Austel (regulatory authority)
 *
 * The default is of course off.
 */

CONF(ignore_fax_dle, FALSE, CT_BOOL)

/*
 * Output recorded voice samples without header and expect raw voice
 * data on input for playback. This feature is turned off by default.
 */

CONF(raw_data, FALSE, CT_BOOL)

/*
 * This is the default compression mode for vgetty for incoming voice
 * messages and for the recording option of vm. The mode 0 is a special
 * mode, that will automatically choose a sane default value for every
 * modem. The default is 0.
 */

CONF(rec_compression, 0, CT_INT)

/*
 * This is the default recording speed for vgetty for incoming voice
 * messages and for the recording option of vm. It is the number of samples
 * per second. The speed 0 is a special speed, that will automatically
 * choose a sane default value for every modem. The default is 0.
 */

CONF(rec_speed, 0, CT_INT)

/*
 * Silence detection length in 0.1 seconds. If the modem detects silence
 * for this time, it sends a silence detect to the host. Default is
 * 7 seconds (70 * 0.1 seconds).
 */

CONF(rec_silence_len, 70, CT_INT)

/*
 * Silence detection threshold in percent (0% to 100%). Increase this value
 * if you have a noisy phone line and the silence detection doesn't work
 * reliably. The default is 40%.
 */

CONF(rec_silence_threshold, 40, CT_INT)

/*
 * If REC_REMOVE_SILENCE is enabled, the trailing silence of an incoming
 * voice message as detected by the modem will be deleted. This might
 * cause you to miss parts of a message if the silence threshold is
 * high and the caller is talking very quietly. To be on the safe side,
 * don't define this. This feature is turned off by default.
 */

CONF(rec_remove_silence, FALSE, CT_BOOL)

/*
 * Maximum recording length in seconds. Hang up if somebody talks
 * longer than this. Default is 5 minutes (300 seconds).
 */

CONF(rec_max_len, 300, CT_INT)

/*
 * Minimum recording length in seconds. Some modems can not detect
 * data or fax modems, so we use the recording time, to decide,
 * what it is. This feature is by default disabled.
 */

CONF(rec_min_len, 6, CT_INT)

/*
 * Enable hardware flow in record and playback mode if the modem
 * supports it. This option is by default on.
 */

CONF(do_hard_flow, TRUE, CT_BOOL)

/*
 * When switching to data or fax mode, always switch to fax mode and
 * enable autodetection of data/fax. Some modems report wrong DLE codes
 * and so the predetection with DLE codes does not work.
 */

CONF(force_autodetect, FALSE, CT_BOOL)

/*
 * Default timeout for the voice watchdog. If this timer expires, the
 * running program will be terminated. The default is 60 seconds.
 */

CONF(watchdog_timeout, 60, CT_INT)

/*
 * Some modems support setting the receive gain. This value can be set in
 * percent (0% to 100%). 0% is off, 100% is maximum. To use the modem
 * default value set this to -1. The default is -1.
 *
 */

CONF(receive_gain, -1, CT_INT)

/*
 * Some modems support setting the transmit gain. This value can be set in
 * percent (0% to 100%). 0% is off, 100% is maximum. To use the modem
 * default value set this to -1. The default is -1.
 *
 */

CONF(transmit_gain, -1, CT_INT)

/*
 * Usually command echo from the modem should be enabled. Since some modems
 * sometimes forget this echo, it is disabled by default. Turning this
 * option off makes things more reliable, but bugs are much harder to trace.
 * So don't ever think about mailing me a bug report with command echo
 * turned off. I will simply ignore it. The default is to disable command
 * echo.
 *
 */

CONF(enable_command_echo, FALSE, CT_BOOL)

/*
 * Time in msec for the delay, when no new data are received from the modem.
 * A higher value will decrease machine load by increasing vgettys reaction
 * time. The default is 10 msec.
 */

CONF(poll_interval, 10, CT_INT)

/*
 * The ML 56k Office, Internet (I), pro and Basic 
 * with actual firmware support 2 commandsets:
 * The one in Elsa.c wich is autodetected and
 * the ITU V253 (if you say TRUE here for this modems you also have to set
 * rec_speed 7200)
 */
CONF(forceV253, FALSE, CT_BOOL)

/*
 * Some modems follow the voice cammands defined in ITU V.253
 * but don't support the flow control command AT+IFC defined in ITU V.250.
 * For those modems you could use the V253ugly driver, which use all of V253modem
 * but for the flow control command it uses simple "AT"
 */
CONF(forceV253subset, FALSE, CT_BOOL)

/*
 * Enable querrying of valid voice compression mode mappings for your modem.
 * Otherwise use defaults only. (Currently only for V253modem supported)
 */
CONF(enable_compression_mapping_querry, TRUE, CT_BOOL)

/*
 * Default entries for the V253_init_compression_table, which will be used,
 * for the AT+VSM=<compression_method>,<sample_rate> command,
 * if compression mapping querry fails or is disabled.
 */
CONF(compression_8bit_linear_signed, 0, CT_INT) // compression 9 for rmd/pvf tools
CONF(compression_16bit_linear_signed, 0, CT_INT) // compression 12 for rmd/pvf tools
CONF(compression_8bit_linear_unsigned, 1 ,CT_INT) // compression 1 for rmd/pvf tools
CONF(compression_8bit_ulaw,    4, CT_INT) // compression 10 for rmd/pvf tools
CONF(compression_8bit_alaw,    5, CT_INT) // compression 11 for rmd/pvf tools
CONF(compression_2bit_adpcm, 140, CT_INT) // compression 2 for rmd/pvf tools
CONF(compression_4bit_adpcm, 141, CT_INT) // compression 4 for rmd/pvf tools
CONF(compression_4bit_ima_adpcm, 129, CT_INT) // compression 5 for rmd/pvf tools

/*
 * Default values for vgetty
 * -------------------------
 */

/*
 * Default number of rings to wait before picking up the phone.
 *
 * Instead of a number, you can also give a file name, that contains
 * a single number with the desired number of rings. Vgetty will
 * automatically append the name of the modem device to the file name.
 * The file name must be an absolut path starting with a leading "/".
 * E.g. #define RINGS "/etc/answer" and the modem device is ttyS0, will
 * lead to the file name "/etc/answer.ttyS0".
 *
 * The default is "3"
 */

CONF(rings, STRING "3", CT_STRING)

/*
 * Default answer mode when vgetty picks up the phone after incoming
 * rings.
 *
 * If this string starts with a "/", vgetty gets the answer mode from
 * the file name given in the string.
 *
 * The default is "voice:fax:data".
 */

CONF(answer_mode, STRING "voice:fax:data", CT_STRING)

/*
 * If vgetty knows that there are new messages (the flag file exists),
 * it will turn on the AA lamp on an external modem and enable the toll
 * saver - it will answer the phone TOLL_SAVER_RINGS earlier than the
 * default. This feature is turned off by default.
 */

CONF(toll_saver_rings, 0, CT_INT)

/*
 * Should the recorded voice message file be kept even if data, fax or
 * DTMF codes were detected? If this is set, vgetty never deletes
 * a recording, if it is not set it will delete the recording, if an
 * incoming data or fax call is detected or if DTMF codes were send. Also
 * this should work in nearly every situation, it makes You loose the
 * recording, if the caller "plays" with DTMF codes to make the message
 * even more beautiful. This feature is enabled by default.
 */

CONF(rec_always_keep, TRUE, CT_BOOL)

/*
 * Primary voice directory for vgetty.
 */

CONF(voice_dir, STRING "/var/spool/voice", CT_STRING)

/*
 * Default owner, group, and file mode for incoming voice messages
 */

CONF(phone_owner, STRING "root", CT_STRING)
CONF(phone_group, STRING "phone", CT_STRING)
CONF(phone_mode, 0660, CT_INT)

/*
 * Location of the flag file for new incoming messages relative to the
 * primary voice directory.
 */

CONF(message_flag_file, STRING ".flag", CT_STRING)

/*
 * Location where vgetty stores the incoming voice messages relative to
 * the primary voice directory.
 */

CONF(receive_dir, STRING "incoming", CT_STRING)

/*
 * Directory containing the messages for vgetty (greeting, handling the
 * answering machine) relative to the primary voice directory.
 */

CONF(message_dir, STRING "messages", CT_STRING)

/*
 * Name of the file in MESSAGE_DIR that contains the names of
 * the greeting message files (one per line, no white space).
 */

CONF(message_list, STRING "Index", CT_STRING)

/*
 * Filename of a backup greeting message in MESSAGE_DIR (used if
 * the random selection fails to find a message).
 */

CONF(backup_message, STRING "standard", CT_STRING)

/*
 * The programs defined below get called by vgetty.
 *
 * Define an empty program name, if you want to disabled one of those
 * programs.
 */

/*
 * There are two separate uses for the Data/Voice button:
 *
 * - If a RING was detected recently, answer the phone in fax/data mode
 * - Otherwise, call an external program to play back messages
 *
 * If you don't define BUTTON_PROGRAM, vgetty will always pick up
 * the phone if Data/Voice is pressed.
 *
 * The default value is "".
 */

CONF(button_program, STRING "", CT_STRING)

/*
 * Program called when the phone is answered, this is instead
 * of the normal behaviour. Don't define this unless you want
 * to e.g. set up a voice mailbox where the normal answering
 * machine behaviour would be inappropiate. The C code is probably
 * more stable and uses less resources.
 *
 * The default value is "".
 */

CONF(call_program, STRING "", CT_STRING)

/*
 * Program called when a DTMF command in the form '*digits#' is received.
 * The argument is the string of digits received (without '*' and '#').
 * The default value is "dtmf.sh".
 */

CONF(dtmf_program, STRING "dtmf.sh", CT_STRING)

/*
 * Program called when a voice message has been received.
 * The argument is the filename of the recorded message.
 * The default value is "".
 */

CONF(message_program, STRING "", CT_STRING)

/*
 * Should vgetty use the AA LED on some modems to indicate that new
 * messages have arrived? This is done by setting the modem register
 * S0 to a value of 255. Some modems have a maximum number of rings
 * allowed and autoanswer after this, so they can not use this feature.
 * This option is by default off.
 */

CONF(do_message_light, FALSE, CT_BOOL)

/*
 * Default values for vm
 * ---------------------
 */

/*
 * If set, will be played prior to (and in addition to) any other
 * greeting message.
 */
CONF(pre_message, STRING "", CT_STRING)

/*
 * If set, will be played instead of the standard "beep"
 */
CONF(beepsound, STRING "", CT_STRING)

/*
 * Frequency for the beep command in Hz. The default is 933Hz.
 */

CONF(beep_frequency, 933, CT_INT)

/*
 * Length for the beep command in msec. The default is 1.5 seconds
 * (1500 * 0.001 seconds).
 */

CONF(beep_length, 1500, CT_INT)

/*
 * Number of tries to open a voice modem device. The default is 3.
 */

CONF(max_tries, 3, CT_INT)

/*
 * Delay between two tries to open a voice device in seconds. The default
 * is 5 seconds.
 */

CONF(retry_delay, 5, CT_INT)

/*
 * Timeout for a dialout operation in seconds. The default is 90 seconds.
 */

CONF(dialout_timeout, 90, CT_INT)

/* -- alborchers@steinerpoint.com
 * Timeout for deciding that a dialout call has been answered; if more
 * than this many 1/10ths of a second have passed since the last ringback,
 * the modem assumes the call has been answered and the ATDT... command
 * exits with response VCON.  A value of 0 causes ATDT... to return VCON
 * immediately.  Default is 70 (7 sec).
 */

CONF(ringback_goes_away, 70, CT_INT)

/* -- alborchers@steinerpoint.com
 * Timeout for deciding that a dialout call has been answered; if more
 * than this many 1/10ths of a second have passed without any ringback
 * the modem assumes the call has been answered and the ATDT... command
 * exits with response VCON.  A value of 0 causes ATDT... to return VCON
 * immediately.  Default is 100 (10 sec).
 */

CONF(ringback_never_came, 100, CT_INT)


/*
 * ring_report_delay:
 * This value determines the delay in /10 seconds between the falling edge
 * of the ring-signal (DRON response) and the RING response.
 * This value should be greater than the expected off-time within a
 * distinctive ring (DROF response). So says the ITU V.253, but it seems that
 * ring_report_delay should be greater than the mentioned DROF AND the
 * following DRON, and shorter than the long DROF!
 * Example with ring_report_delay = 10 (2/10 sec per char):
 *               ^
 *    ring-pulse | ...____###__##_______###__##_______###__##______....
 *                          | | |    | |  | | |    | |  | | |
 *                          DRON=6        DRON=6        DRON=6
 *                            DROF=4        DROF=4        DROF=4
 *                              DRON=4        DRON=4        DRON=4
 *                                   RING          RING
 *                                     DROF=14       DROF=14
 *                                                        time --->
 *
 * Default is 15 (1.5 sec)
 */
CONF(ring_report_delay, 15, CT_INT)

/*
 * Default values for the pvf tools
 * --------------------------------
 */

/*
 * There are currently no defaults.
 */

CONF(voice_devices, STRING "", CT_STRING)
