/*
 * voice_hardware.h
 *
 * Defines the structure with data and routines for the hardware drivers.
 *
 * $Id: hardware.h,v 1.20 2005/03/13 17:27:42 gert Exp $
 *
 */

/*
 * Structure with voice modem hardware informations and functions
 */

/* Voice modem quirks masks */
typedef unsigned char vmq_t;
#define VMQ_NEEDS_SET_DEVICE_BEFORE_ANSWER 1

typedef struct
     {
     char *name;
     char *rmd_name;
     char *pick_phone_cmnd;
     char *pick_phone_answr;
     char *beep_cmnd;
     char *beep_answr;
     int   beep_timeunit;
     char *hardflow_cmnd;
     char *hardflow_answr;
     char *softflow_cmnd;
     char *softflow_answr;
     char *start_play_cmnd;
     char *start_play_answr;
     char *reset_play_cmnd;
     char *intr_play_cmnd;
     char *intr_play_answr;
     char *stop_play_cmnd;
     char *stop_play_answr;
     char *start_rec_cmnd;
     char *start_rec_answr;
     char *stop_rec_cmnd;
     char *stop_rec_answr;
     char *switch_mode_cmnd;
     char *switch_mode_answr;
     char *ask_mode_cmnd;
     char *ask_mode_answr;
     char *voice_mode_id;
     char *play_dtmf_cmd;
     char *play_dtmf_extra;
     char *play_dtmf_answr;
     // juergen.kosel@gmx.de : voice-duplex-patch start
     char *start_duplex_voice_cmnd;
     char *start_duplex_voice_answr;
     char *stop_duplex_voice_cmnd;
     char *stop_duplex_voice_answr;
     // juergen.kosel@gmx.de : voice-duplex-patch end
     int (*answer_phone) (void);
     int (*beep) (int frequency, int duration);
     int (*dial) (char* number);
     int (*handle_dle) (char code);
     int (*init) (void);
     int (*message_light_off) (void);
     int (*message_light_on) (void);
     int (*start_play_file) (void);
     int (*reset_play_file) (void);
     int (*stop_play_file) (void);
     int (*play_file) (FILE *fd, int bps);
     int (*record_file) (FILE *fd, int bps);
     int (*set_compression) (int *compression, int *speed, int *bits);
     int (*set_device) (int device);
     int (*stop_dialing) (void);
     int (*stop_playing) (void);
     int (*stop_recording) (void);
     int (*stop_waiting) (void);
     int (*switch_to_data_fax) (char* mode);
     int (*voice_mode_off) (void);
     int (*voice_mode_on) (void);
     int (*wait) (int timeout);
     int (*play_dtmf) (char* number);
     int (*check_rmd_adequation) (char *rmd_name); /* not NUL terminated */
     // juergen.kosel@gmx.de : voice-duplex-patch start
     int (*handle_duplex_voice) (FILE *tomodem, FILE *frommodem, int bps);
     int (*stop_duplex_voice) (void);
     // juergen.kosel@gmx.de : voice-duplex-patch end
     vmq_t voice_modem_quirks;
     } voice_modem_struct;

/*
 * Global variables
 */

extern voice_modem_struct *voice_modem;
#define voice_modem_name voice_modem->name
#define voice_modem_rmd_name voice_modem->rmd_name
extern int voice_modem_state;
extern int rom_release;

/*
 * Hardware handle event functions
 */

extern voice_modem_struct no_modem;
extern voice_modem_struct Cirrus_Logic;
extern voice_modem_struct Dolphin;
extern voice_modem_struct Digi_RAS;
extern voice_modem_struct Dr_Neuhaus;
extern voice_modem_struct Elsa;
extern voice_modem_struct V253modem;
extern voice_modem_struct V253ugly;
extern voice_modem_struct IS_101;
extern voice_modem_struct ISDN4Linux;
extern voice_modem_struct Supra;
extern voice_modem_struct Supra56ePRO;
extern voice_modem_struct Multitech_2834ZDXv;
extern voice_modem_struct Multitech_5634ZBAV;
extern voice_modem_struct Multitech_5600ZDXv;
extern voice_modem_struct Multitech_5634ZPX;
extern voice_modem_struct Multitech_5634ZPX_ISA;
extern voice_modem_struct Rockwell;
extern voice_modem_struct Sierra;
extern voice_modem_struct UMC;
extern voice_modem_struct US_Robotics;
extern voice_modem_struct ZyXEL_1496;
extern voice_modem_struct ZyXEL_2864;
extern voice_modem_struct ZyXEL_Omni56K;
extern voice_modem_struct Lucent;

