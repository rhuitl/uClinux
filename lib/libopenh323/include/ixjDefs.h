/*
	ixjDefs.h

	Copyright (c) 1996-1998, Quicknet Technologies, Inc.
	All Rights Reserved.

	Internet PhoneJACK, Internet LineJACK, etc. definitions.

    -----------------------------------------------------------------

	$Header: /cvsroot/openh323/openh323/include/ixjDefs.h,v 1.4 2002/03/21 21:21:10 craigs Exp $

  $Log: ixjDefs.h,v $
  Revision 1.4  2002/03/21 21:21:10  craigs
  Move idb stuff to separate file

	
*/

#ifndef _IXJDEFS_H
#define _IXJDEFS_H

#include <ixjIdb.h>

//==========================================================================
//==========================================================================
//
//	Constants and structures for Quicknet's Internet PhoneJACK and
//	Internet LineJACK cards.
//
//==========================================================================

//------------------------------------------------
//	Plug and Play IDs
//------------------------------------------------
#define MODEL_INTERNET_PHONEJACK		0x0100
#define MODEL_INTERNET_BLACKJACK		0x0200
#define MODEL_INTERNET_LINEJACK			0x0300
#define MODEL_INTERNET_PHONEJACK_LITE	0x0400
#define MODEL_INTERNET_PHONEJACK_PCI	0x0500
#define MODEL_INTERNET_PHONEJACK_TJPCI	0x0501
#define MODEL_INTERNET_PHONECARD		0x0600

//--------------------------------------------------------------------------
//	Codec support
//--------------------------------------------------------------------------
//
#define CODEC_RATE_4000Hz  4000
#define CODEC_RATE_5500Hz  5500
#define CODEC_RATE_6000Hz  6000
#define CODEC_RATE_7333Hz  7333
#define CODEC_RATE_8000Hz  8000
#define CODEC_RATE_11025Hz 11025
#define CODEC_RATE_16000Hz 16000
#define CODEC_RATE_22050Hz 22050
#define CODEC_RATE_32000Hz 32000
#define CODEC_RATE_33075Hz 33075
#define CODEC_RATE_44100Hz 44100
#define CODEC_RATE_48000Hz 48000

#define OLD_CODEC_RATE_4000Hz  1000
#define OLD_CODEC_RATE_5500Hz  1010
#define OLD_CODEC_RATE_6000Hz  1020
#define OLD_CODEC_RATE_7333Hz  1030
#define OLD_CODEC_RATE_8000Hz  1040
#define OLD_CODEC_RATE_11025Hz 1050
#define OLD_CODEC_RATE_16000Hz 1060
#define OLD_CODEC_RATE_22050Hz 1070
#define OLD_CODEC_RATE_32000Hz 1080
#define OLD_CODEC_RATE_33075Hz 1090
#define OLD_CODEC_RATE_44100Hz 1100
#define OLD_CODEC_RATE_48000Hz 1110

//	XTAL = 3.8912 MHz
//	Clock = 10*XTAL = 38.912 MHz
//
//	Rules:
//		SCLK = Clock/(N+1)
//		FSYNC = SCLK/(M+1)
//
//		4 <= (N+1) <= 32
//		For 8-bit Codec:  SCLK >= 16*FSYNC
//		For 16-bit Codec: SCLK >= 32*FSYNC
//
//	8Khz Playback/Record:
//		SCLK = Clock/( 18+1) = 2.048 MHz
//		FSYNC = SCLK/(255+1) =  8000 Hz ( 8,000.0 Hz =   8,000 Hz standard + 0%)
//	11Khz Playback/Record:
//		SCLK = Clock/( 13+1) = 2.779 MHz
//		FSYNC = SCLK/(251+1) =  11025 Hz (11,029.5 Hz = 11,025 Hz standard + -0.04%)
//	22Khz Playback/Record:
//		SCLK = Clock/( 9+1)  = 3.8912 MHz
//		FSYNC = SCLK/(175+1) =  22050 Hz (22,109.1 Hz = 22,050 Hz standard + ?.?%) +59.1
//
//		SCLK = Clock/( 13+1) = 2.779 MHz
//		FSYNC = SCLK/(125+1) =  22050 Hz (22,059.0 Hz = 22,050 Hz standard + ?.?%) 
//

//	XTAL = 3.8912 MHz
//	Clock = 10*XTAL = 38.912 MHz
//
//	SCLK = Clock/( 18+1) = 2.048 MHz
//	FSYNC = SCLK/(371+1) =  5505 Hz ( 5,505.4 Hz =  5,500 Hz standard + x%)
//	FSYNC = SCLK/(340+1) =  6006 Hz ( 6,005.9 Hz =  6,000 Hz standard + x%)
//	FSYNC = SCLK/(278+1) =  7341 Hz ( 7,340.5 Hz =  7,333 Hz standard + x%)
//	FSYNC = SCLK/(255+1) =  8000 Hz ( 8,000.0 Hz =  8,000 Hz standard + 0%)
//	FSYNC = SCLK/(127+1) = 16000 Hz (16,000.0 Hz = 16,000 Hz standard + 0%)
//	FSYNC = SCLK/( 63+1) = 32000 Hz (32,000.0 Hz = 32,000 Hz standard + 0%)
//	FSYNC = SCLK/( 61+1) = 33032 Hz (33,032.3 Hz = 33,075 Hz standard + x%)
//	FSYNC = SCLK/( 45+1) = 44522 Hz (44,521.7 Hz = 44,100 Hz standard + x%)
//	FSYNC = SCLK/( 42+1) = 47628 Hz (47,627.9 Hz = 48,000 Hz standard - x%)

//	Selects: Sets the division factor used to divide the SCLK clock to generate FSYNC.
#define CODEC_FSYNC_RATE_371 371
#define CODEC_FSYNC_RATE_340 340
#define CODEC_FSYNC_RATE_278 278
#define CODEC_FSYNC_RATE_255 255
#define CODEC_FSYNC_RATE_251 251
#define CODEC_FSYNC_RATE_185 185
#define CODEC_FSYNC_RATE_175 175
#define CODEC_FSYNC_RATE_127 127
#define CODEC_FSYNC_RATE_125 125
#define CODEC_FSYNC_RATE_92   92
#define CODEC_FSYNC_RATE_63   63
#define CODEC_FSYNC_RATE_61   61
#define CODEC_FSYNC_RATE_45   45
#define CODEC_FSYNC_RATE_42   42

//	Selects: Sets the division factor used to divide the main CT8020 clock to generate SCLK.
#define CODEC_CO_RATE_9 9
#define CODEC_CO_RATE_13 13
#define CODEC_CO_RATE_19 19
#define CODEC_CO_RATE_18 18

const WORD CODEC_WIDTH_8BIT  = 0;	//	Selects 8-bit Mu-law codec.
const WORD CODEC_WIDTH_16BIT = 1;	//	Selects 16-bit linear codec.

const WORD CODEC_LAW_MULAW = 0;	//	Selects external Mu-law codec.

const WORD CODEC_MASTER_SLAVE  = 0;	//	Selects save mode (FSYNC and SCLK are inputs - default after reset).
const WORD CODEC_MASTER_MASTER = 1;	//	Selects master mode (FSYNC and SCLK are outputs).

const WORD CODEC_LONG_SHORTFRAME = 0;	//	Selects short frame sync mode when WIDE=0.
const WORD CODEC_LONG_LONGFRAME  = 1;	//	Selects long frame sync mode when WIDE=1.

const WORD CODEC_OUTPUT_CODEC_DEFAULT = 0;	//	Selects: default output codec routing.
const WORD CODEC_OUTPUT_CODEC_CODEC1  = 1;	//	Selects: output signal goes to codec 1 only.
const WORD CODEC_OUTPUT_CODEC_CODEC0  = 2;	//	Selects: output signal goes to codec 0 only.
const WORD CODEC_OUTPUT_CODEC_BOTH    = 3;	//	Selects: output signal goes to both codec 0 and codec 1.

const WORD CODEC_INPUT_CODEC_NORMAL   = 0;	//	Selects: normal input codec routing.
const WORD CODEC_INPUT_CODEC_EXCHANGE = 1;	//	Selects: input from codec 0 and codec 1 exchanged.

const WORD CODEC_SET_RATE_NOACTION = 0;	//	Selects: no action.
const WORD CODEC_SET_RATE_NEXTCMD  = 1;	//	Selects: next command word programs codec sample rate dividers.

const WORD CODEC_WIDE_1SCLK      = 0;		//	Selects: FSYNC is 1 SCLK period wide.
const WORD CODEC_WIDE_8OR16SCLKS = 1;		//	Selects: FSYNC is 8 SCLK periods wide if Width=0 or 16 SCLK periods wide if Width=1.

const DWORD XTAL_38912 = 3891200;
const DWORD XTAL_4000 = 4000000;
const DWORD XTAL_4096 = 4096000;

const DWORD SCLK_2048 = 2048000;
const DWORD SCLK_512 = 512000;
const DWORD SCLK_1024 = 1024000;
const DWORD SCLK_2000 = 2000000;
const DWORD SCLK_MAX = 1835008; // 300373; // 2097152; // 2095600;

//==========================================================================
//--------------------------------------------------------------------------
//	Compression/Decompression support
//--------------------------------------------------------------------------
//
#define COMPRESS_MODE_TRUESPEECH  0	//	Selects: TrueSpeech 8.5, 6.3, 5.3, 4.8 or 4.1 Kbps
#define COMPRESS_MODE_ULAW        2	//	Selects: 64 Kbit/sec U-law PCM
#define COMPRESS_MODE_16LINEAR    6	//	Selects: 128 Kbit/sec 16-bit linear
#define COMPRESS_MODE_8LINEAR     4	//	Selects: 64 Kbit/sec 8-bit signed linear
#define COMPRESS_MODE_8LINEAR_WSS 5	//	Selects: 64 Kbit/sec WSS 8-bit unsigned linear

//	TrueSpeech compress modes: 8.5 - 4.1
#define COMPRESS_RATE_TS85 0	//	Selects TrueSpeech 8.5 play mode.
#define COMPRESS_RATE_TS63 1	//	Selects TrueSpeech 6.3 play mode.
#define COMPRESS_RATE_TS53 2	//	Selects TrueSpeech 5.3 play mode.
#define COMPRESS_RATE_TS48 3	//	Selects TrueSpeech 4.8 play mode.
#define COMPRESS_RATE_TS41 4	//	Selects TrueSpeech 4.1 play mode.

//	G.723.1 record/compress modes: 6.3 & 5.3
//	NOTE: Same as TrueSpeech 6.3 & 5.3 modes.
#define COMPRESS_RATE_G7231_TS63 1	//	Selects TrueSpeech 6.3 play mode.
#define COMPRESS_RATE_G7231_TS53 2	//	Selects TrueSpeech 5.3 play mode.

// ------------------------

#define COMPRESS_FRAME_TRUESPEECH  0	//	TrueSpeech 8.5, 6.3, 5.3, 4.8 or 4.1 Kbps
#define COMPRESS_FRAME_ULAW        120	//	64 Kbit/sec U-law PCM
#define COMPRESS_FRAME_16LINEAR    240	//	128 Kbit/sec 16-bit linear
#define COMPRESS_FRAME_8LINEAR     120	//	64 Kbit/sec 8-bit signed linear
#define COMPRESS_FRAME_8LINEAR_WSS 120	//	64 Kbit/sec WSS 8-bit unsigned linear

//	TrueSpeech recording modes: 8.5 - 4.1
#define COMPRESS_FRAME_TS85 16	//	TrueSpeech 8.5 record frame.
#define COMPRESS_FRAME_TS63 12	//	TrueSpeech 6.3 record frame.
#define COMPRESS_FRAME_TS53 10	//	TrueSpeech 5.3 record frame.
#define COMPRESS_FRAME_TS48 9		//	TrueSpeech 4.8 record frame.
#define COMPRESS_FRAME_TS41 8		//	TrueSpeech 4.1 record frame.

//	G.723.1 recording modes: 6.3 & 5.3
//	NOTE: Same as TrueSpeech 6.3 & 5.3 modes.
#define COMPRESS_FRAME_G7231_TS63 COMPRESS_FRAME_TS63	//	TrueSpeech 6.3 record frame.
#define COMPRESS_FRAME_G7231_TS53 COMPRESS_FRAME_TS53	//	TrueSpeech 5.3 record frame.

#define COMPRESS_MAX_BUFFER_SIZE COMPRESS_FRAME_16LINEAR	//	Max buffer size: Tx or Rx.

//	Additional bit patterns to 'Or' into Command Base 'words'
const WORD COMPRESS_TFRMODE_80X5 = 0;	//	Selects Data transfer via Software Control and Status Registers (CT8015/CT8005 protocol mode).
const WORD COMPRESS_TFRMODE_8020 = 3;	//	Selects Data transfer via Host Transmit Data Buffer Access Port.

const WORD COMPRESS_SYNC_MODE_CODEC = 0;
const WORD COMPRESS_SYNC_MODE_DATA  = 1;
const WORD COMPRESS_SYNC_MODE_POLL  = 2;
const WORD COMPRESS_SYNC_MODE_HOST  = 3;

//==========================================================================
//--------------------------------------------------------------------------
//	Device support
//--------------------------------------------------------------------------
//
//	Additional bit patterns to 'Or' into Command Base 'words'
//const WORD DEVCTRL_TONE_MODE_SYNC  = 0;	//	Selects Synchronous Tone mode
//const WORD DEVCTRL_TONE_MODE_ASYNC = 1;	//	Selects Asynchronous Tone mode

// Analog source for the Codec #1.
//	Analog source is determined by the GPIO bits: 6 & 7.
//					| GPIO6	| GPIO7	|
//------------------|-------|-------|-------
//	POTS Phone		|   0	|   0	|
//	Speakerphone	|   0	|   1	|
//	Handset Phone	|   1	|   0	|
//	  ??????		|   1   |   1   |
//-------------------------------------------
//
#define ANALOG_SOURCE_POTSPHONE		(0x0)
#define ANALOG_SOURCE_SPEAKERPHONE	(0x1)
#define ANALOG_SOURCE_HANDSETPHONE	(0x2)
#define ANALOG_SOURCE_PSTNLINE		(0x2)

#define LINEJACK_MODE_PHONEJACK		(0x0)
#define LINEJACK_MODE_LINEJACK		(0x1)
#define LINEJACK_MODE_STANDALONE	(0x2)

#define DEVICE_SPEAKERPHONE 0x01
#define DEVICE_POTS 0x02
#define DEVICE_HANDSET 0x04
#define DEVICE_PSTN 0x08

#define COEFF_US            0
#define COEFF_UK            1
#define COEFF_FRANCE        2
#define COEFF_GERMANY       3
#define COEFF_AUSTRALIA     4
#define COEFF_JAPAN         5
#define COEFF_CTR21         6
#define COEFF_CZECH         7
#define COEFF_GERMANY2      8
#define COEFF_ITALY         9
#define COEFF_SOUTH_KOREA  10
#define COEFF_NEW_ZEALAND  11
#define COEFF_NORWAY       12
#define COEFF_PHILIPPINES  13
#define COEFF_POLAND       14
#define COEFF_SOUTH_AFRICA 15
#define COEFF_SWEDEN       16

// SLIC States
//	SLIC State is determined by the GPIO bits: 1,2,3
//					| GPIO3	| GPIO2	| GPIO1	| !GPIO1 |
//					|   C3	|   C2	|   C1	|  B2EN	 |
//------------------|-------|-------|-------|--------|
//	Open Circuit	|   0	|   0	|   0	|   1	 |
//	Ringing   		|   0	|   0	|   1	|   0	 |
//	Active       	|   0	|   1	|   0	|   1	 |
//----------------------------------------------------
//
#define SLIC_STATE_OPENCIRCUIT	0
#define SLIC_STATE_RINGING		1
#define SLIC_STATE_ACTIVE		2
#define SLIC_STATE_OHT			3
#define SLIC_STATE_TIPOPEN		4
#define SLIC_STATE_STANDBY		5
#define SLIC_STATE_APR			6
#define SLIC_STATE_OHTPR		7

// Switch Hook States
//	Switch Hook State is determined by GPIO 5
//					| GPIO5	 |
//------------------|--------|
//	Off Hook		|   0	 |
//	On Hook			|   1	 |
//----------------------------
//
#define SLIC_OFF_HOOK	(0x0)
#define SLIC_ON_HOOK	(0x1)

// LineJack Test error codes
#define LINE_TEST_OK 0
#define LINE_TEST_TESTING 1
#define LINE_TEST_POTS_OFF_HOOK 2
#define LINE_TEST_LINE_CONNECTED_TO_POTS 3
#define LINE_TEST_NO_LINE_PRESENT 4

// The ring pattern is a 12-bit sequence.
// Each bit represents 1/2 second of ring
// on or off for a total of 6 seconds.
#define RING_PATTERN_MASK (0x0FFF)

#define DEVCTRL_HOOKSTATE_INIT			0
#define DEVCTRL_HOOKSTATE_ON_HOOK_1		1
#define DEVCTRL_HOOKSTATE_ON_HOOK_2		2
#define DEVCTRL_HOOKSTATE_ON_HOOK_3		3
#define DEVCTRL_HOOKSTATE_OFF_HOOK_1	4
#define DEVCTRL_HOOKSTATE_OFF_HOOK_2	5
#define DEVCTRL_HOOKSTATE_OFF_HOOK_3	6

#define DEVCTRL_RINGSTATE_INIT		0
#define DEVCTRL_RINGSTATE_RING_0	1
#define DEVCTRL_RINGSTATE_RING_1	2
#define DEVCTRL_RINGSTATE_RING_2	3
#define DEVCTRL_RINGSTATE_RING_3	4
#define DEVCTRL_RINGSTATE_RING_4	5
#define DEVCTRL_RINGSTATE_RING_5	6
#define DEVCTRL_RINGSTATE_RING_6	7
#define DEVCTRL_RINGSTATE_RING_7	8
#define DEVCTRL_RINGSTATE_RING_8	9
#define DEVCTRL_RINGSTATE_RING_9	10
#define DEVCTRL_RINGSTATE_RING_10	11
#define DEVCTRL_RINGSTATE_RING_11	12

//==========================================================================
//--------------------------------------------------------------------------
//	Filter support
//--------------------------------------------------------------------------
//
//	Additional bit patterns to 'Or' into Command Base 'words'
#define FILTER_MODE_SYNC  0
#define FILTER_MODE_ASYNC 1

#define FILTER_LINE_VOLUME_POS_0DB 2	//	+0 dB
#define FILTER_LINE_VOLUME_MUTE    3	//	Mute Microphone (also resets AEC)

#define FILTER_SPEAKER_VOLUME_POS_14DB 0	//	+14 dB
#define FILTER_SPEAKER_VOLUME_POS_12DB 1	//	+12 dB
#define FILTER_SPEAKER_VOLUME_POS_10DB 2	//	+10 dB
#define FILTER_SPEAKER_VOLUME_POS_8DB  3	//	+8 dB
#define FILTER_SPEAKER_VOLUME_POS_6DB  4	//	+6 dB
#define FILTER_SPEAKER_VOLUME_POS_4DB  5	//	+4 dB
#define FILTER_SPEAKER_VOLUME_POS_2DB  6	//	+2 dB
#define FILTER_SPEAKER_VOLUME_POS_0DB  7	//	0 dB
#define FILTER_SPEAKER_VOLUME_NEG_2DB  8	//	-2 dB
#define FILTER_SPEAKER_VOLUME_NEG_4DB  9	//	-4 dB
#define FILTER_SPEAKER_VOLUME_NEG_6DB  10	//	-6 dB
#define FILTER_SPEAKER_VOLUME_NEG_8DB  11	//	-8 dB
#define FILTER_SPEAKER_VOLUME_NEG_10DB 12	//	-10 dB
#define FILTER_SPEAKER_VOLUME_NEG_12DB 13	//	-12 dB
#define FILTER_SPEAKER_VOLUME_NEG_14DB 14	//	-14 dB
#define FILTER_SPEAKER_VOLUME_MUTE     15	//	Mute Filter

#define FILTER_DTMFSTATE_INIT			0
#define FILTER_DTMFSTATE_NOT_VALID_1	1
#define FILTER_DTMFSTATE_NOT_VALID_2	2
#define FILTER_DTMFSTATE_NOT_VALID_3	3
#define FILTER_DTMFSTATE_VALID_1		4
#define FILTER_DTMFSTATE_VALID_2		5
#define FILTER_DTMFSTATE_VALID_3		6

#define FrameCount( LineMonitor ) ((LineMonitor>>12)&0x0f)
#define FilterBits( LineMonitor ) ((LineMonitor>>8)&0x0f)
#define Peak( LineMonitor ) ((LineMonitor>>6)&1)
#define DTMFValid( LineMonitor ) ((LineMonitor>>5)&1)
#define CPFValid( LineMonitor ) ((LineMonitor>>4)&1)
#define DTMFDigit( LineMonitor ) (LineMonitor&0x0f)


//==========================================================================
//--------------------------------------------------------------------------
//	Idle support
//--------------------------------------------------------------------------
//
#define IDLE_TONE_MODE_SYNC  0	//	Selects Synchronous Tone mode
#define IDLE_TONE_MODE_ASYNC 1	//	Selects Asynchronous Tone mode

#define IDLE_TONE_NOTONE	0
#define IDLE_TONE_1		1
#define IDLE_TONE_2		2
#define IDLE_TONE_3		3
#define IDLE_TONE_4		4
#define IDLE_TONE_5		5
#define IDLE_TONE_6		6
#define IDLE_TONE_7		7
#define IDLE_TONE_8		8
#define IDLE_TONE_9		9
#define IDLE_TONE_STAR	10
#define IDLE_TONE_0		11
#define IDLE_TONE_POUND	12
#define IDLE_TONE_DIAL	25
#define IDLE_TONE_RING	26
#define IDLE_TONE_BUSY	27
#define IDLE_TONE_A		28
#define IDLE_TONE_B		29
#define IDLE_TONE_C		30
#define IDLE_TONE_D		31

//	Table from TelTone M-991 Spec sheet (table 4).
//	Tone Name				Frequency (Hz)			Interruption Rate
//							 1			 2
//-------------------------------------------------------------------------------------------
//	Dial				|	350		|	440		|	Steady
//	Reorder				|	480		|	620		|	Repeat, tones on and off 250 ms +- 25ms
//	Busy				|	480		|	620		|	Repeat,	tones on and off 500 ms +- 50ms
//	Audible Ring		|	480		|	480		|	Repeat,	tones on 2 +- 0.2sec, tones off 4 +- 0.4sec
//	Recall Dial			|	350		|	440		|	Three bursts tones on and off 100 ms +- 20ms each followed by dial tone
//	Special AR			|	440		|	480		|	Tones on 1 +- 0.2sec, followed by single 440Hz on for 0.2sec on, and silence for 3 +- 0.3sec, repeat
//	Intercept			|	440		|	620		|	Repeat alternating tones, each on for 230ms +- 70ms with total cycle of 500 +- 50ms
//	Call Waiting		|	440		|	Off		|	One burst 200 +- 100ms
//	Busy Verification	|	440		|	Off		|	One burst of tone on 1.75 +- 0.25sec before attendant intrudes, followed by burst of tone 0.65 +- 0.15sec on, 8 to 20 sec apart for as long as the call lasts.
//	Executive Override	|	440		|	Off		|	One burst of tone for 3 +- 1sec before overriding station intrudes.
//	Confirmation		|	350		|	440		|	Three bursts on and off 100ms each or 100ms on, 100ms off, 300 ms on.

#define TONE_DIAL				0
#define	TONE_REORDER			1
#define TONE_BUSY				2
#define	TONE_AUDIBLE_RING		3
#define	TONE_RECALL_DIAL		4
#define	TONE_SPECIAL_AR			5
#define	TONE_INTERCEPT			6
#define	TONE_CALL_WAITING		7
#define	TONE_BUSY_VERIFICATION	8
#define	TONE_EXECUTIVE_OVERRIDE	9
#define	TONE_CONFIRMATION		10

typedef struct
{
    DWORD dwToneIndex;
    DWORD dwDuration;
	DWORD dwToneOnPeriod;
	DWORD dwToneOffPeriod;
	DWORD dwMasterGain;
} IDLE_TONE;

typedef struct
{
    DWORD dwToneIndex;   // 1-31, 0 reserved for silence
    DWORD dwFrequencyFactor0; // dwFrequencyFactor0 = 32767 * cos( 2*Pi*(frequency0/8000) )
	DWORD dwGain0;   // 0-15 See Tone Level Table
    DWORD dwFrequencyFactor1; // dwFrequencyFactor1 = 32767 * cos( 2*Pi*(frequency1/8000) )
	DWORD dwGain1;   // 0-15 See Tone Level Table
} IDLE_NEW_TONE;

//==========================================================================
// 
// Tone Level Table
//____________________________________________________________
// Index     Codec Output Level (dB relative to 0.707 Vrms)
//____________________________________________________________
//      0                   +6
//      1                   +4
//      2                   +2
//      3                     0
//      4                    -2
//      5                    -4
//      6                    -6
//      7                    -8
//      8                  -10
//      9                  -12
//     10                 -14
//     11                 -16
//     12                 -18
//     13                 -20
//     14                 -22
//     15                 -24

//==========================================================================
//--------------------------------------------------------------------------
//	Mixer support
//--------------------------------------------------------------------------
//
// Playback mixer lines
#define PlaybackMaster			0
#define PlaybackMicrophone		1
#define PlaybackWave			2
#define PlaybackCD				3
#define PlaybackLineIn			4
#define PlaybackPhoneIn			5
#define PlaybackPhoneOut		6
#define PlaybackPhoneLineOut	7
#define PlaybackDeviceCount		8

// Record mixer lines
#define RecordMaster		0
#define RecordMicrophone	1
#define RecordWave			2
#define RecordCD			3
#define RecordLineIn		4
#define RecordPhoneIn		5
#define RecordPhoneLineIn	6
#define RecordDeviceCount	7

// Output mixer lines
#define OutputMicrophone	PlaybackMicrophone
#define OutputWave			PlaybackWave
#define OutputCD			PlaybackCD
#define OutputLineIn		PlaybackLineIn
#define OutputPhoneIn		PlaybackPhoneIn

// Input mixer lines
#define InputMicrophone	RecordMicrophone
#define InputWave		RecordWave
#define InputCD			RecordCD
#define InputLineIn		RecordLineIn
#define InputPhoneIn	RecordPhoneIn

// Mixer line structure
typedef struct _MIXER_LINE
{
    DWORD dwLineID;
    DWORD dwMute;
    DWORD dwLeftVolume;
    DWORD dwRightVolume;
}
MIXER_LINE;

#define MIXER_ACCESS TEXT( "MixerAccess" )

//==========================================================================
//--------------------------------------------------------------------------
//	Playback support
//--------------------------------------------------------------------------
//
//	Additional bit patterns to 'Or' into Command Base 'words'
#define PLAYBACK_TFRMODE_80X5 0	//	Selects Data transfer via Software Control and Status Registers (CT8015/CT8005 protocol mode).
#define PLAYBACK_TFRMODE_8020 3	//	Selects Data transfer via Host Transmit Data Buffer Access Port.

#define PLAYBACK_SYNC_MODE_CODEC	0
#define PLAYBACK_SYNC_MODE_DATA		1
#define PLAYBACK_SYNC_MODE_POLL		2
#define PLAYBACK_SYNC_MODE_HOST		3

//	Playback modes
#define PLAYBACK_MODE_COMPRESSED		0	//	Selects: Compressed modes, TrueSpeech 8.5-4.1, G.723.1, G.722, G.728, G.729
#define PLAYBACK_MODE_TRUESPEECH_V40	0	//	Selects: TrueSpeech 8.5, 6.3, 5.3, 4.8 or 4.1 Kbps
#define PLAYBACK_MODE_TRUESPEECH		8	//	Selects: TrueSpeech 8.5, 6.3, 5.3, 4.8 or 4.1 Kbps Version 5.1
#define PLAYBACK_MODE_ULAW				2	//	Selects: 64 Kbit/sec MuA-law PCM
#define PLAYBACK_MODE_ALAW				10	//	Selects: 64 Kbit/sec A-law PCM
#define PLAYBACK_MODE_16LINEAR			6	//	Selects: 128 Kbit/sec 16-bit linear
#define PLAYBACK_MODE_8LINEAR			4	//	Selects: 64 Kbit/sec 8-bit signed linear
#define PLAYBACK_MODE_8LINEAR_WSS		5	//	Selects: 64 Kbit/sec WSS 8-bit unsigned linear

//	Playback rates
#define PLAYBACK_RATE_TS85		0	//	Selects TrueSpeech 8.5 playback rate.
#define PLAYBACK_RATE_TS63		1	//	Selects TrueSpeech 6.3 playback rate.
#define PLAYBACK_RATE_TS53		2	//	Selects TrueSpeech 5.3 playback rate.
#define PLAYBACK_RATE_TS48		3	//	Selects TrueSpeech 4.8 playback rate.
#define PLAYBACK_RATE_TS41		4	//	Selects TrueSpeech 4.1 playback rate.
#define PLAYBACK_RATE_G722		7	//	Selects G.722 playback rate.
#define PLAYBACK_RATE_G723_63	PLAYBACK_RATE_TS63	//	Selects G.723.1 (6.3 kbps) playback rate.
#define PLAYBACK_RATE_G723_53	PLAYBACK_RATE_TS53	//	Selects G.723.1 (5.3 kbps) playback rate.
#define PLAYBACK_RATE_G728		5	//	Selects G.728 playback rate.
#define PLAYBACK_RATE_G729		6	//	Selects G.729 playback rate.

// Frame sizes in WORD units
#define PLAYBACK_TS85_WORDS				16		//	TrueSpeech 8.5, 30ms frame size
#define PLAYBACK_TS63_WORDS				12		//	TrueSpeech 6.3, 30ms frame size
#define PLAYBACK_TS53_WORDS				10		//	TrueSpeech 5.3, 30ms frame size
#define PLAYBACK_TS48_WORDS				9		//	TrueSpeech 4.8, 30ms frame size
#define PLAYBACK_TS41_WORDS				8		//	TrueSpeech 4.1, 30ms frame size
#define PLAYBACK_ALAW_WORDS				120		//	64 Kbit/sec A-law PCM, 30ms frame size
#define PLAYBACK_ALAW_30MS_WORDS		120		//	64 Kbit/sec A-law PCM, 30ms frame size
#define PLAYBACK_ALAW_20MS_WORDS		80		//	64 Kbit/sec A-law PCM, 20ms frame size
#define PLAYBACK_ALAW_10MS_WORDS		40		//	64 Kbit/sec A-law PCM, 10ms frame size
#define PLAYBACK_ULAW_WORDS				120		//	64 Kbit/sec Mu-law PCM, 30ms frame size
#define PLAYBACK_ULAW_30MS_WORDS		120		//	64 Kbit/sec Mu-law PCM, 30ms frame size
#define PLAYBACK_ULAW_20MS_WORDS		80		//	64 Kbit/sec Mu-law PCM, 20ms frame size
#define PLAYBACK_ULAW_10MS_WORDS		40		//	64 Kbit/sec Mu-law PCM, 10ms frame size
#define PLAYBACK_16LINEAR_WORDS			240		//	128 Kbit/sec 16-bit linear, 30ms frame size
#define PLAYBACK_16LINEAR_30MS_WORDS	240		//	128 Kbit/sec 16-bit linear, 30ms frame size
#define PLAYBACK_16LINEAR_20MS_WORDS	160		//	128 Kbit/sec 16-bit linear, 20ms frame size
#define PLAYBACK_16LINEAR_10MS_WORDS	80		//	128 Kbit/sec 16-bit linear, 10ms frame size
#define PLAYBACK_8LINEAR_WORDS			120		//	64 Kbit/sec 8-bit signed linear, 30ms frame size
#define PLAYBACK_8LINEAR_30MS_WORDS		120		//	64 Kbit/sec 8-bit signed linear, 30ms frame size
#define PLAYBACK_8LINEAR_20MS_WORDS		80		//	64 Kbit/sec 8-bit signed linear, 20ms frame size
#define PLAYBACK_8LINEAR_10MS_WORDS		40		//	64 Kbit/sec 8-bit signed linear, 10ms frame size
#define PLAYBACK_8LINEAR_WSS_WORDS		120		//	64 Kbit/sec WSS 8-bit unsigned linear, 30ms frame size
#define PLAYBACK_8LINEAR_WSS_30MS_WORDS	120		//	64 Kbit/sec WSS 8-bit unsigned linear, 30ms frame size
#define PLAYBACK_8LINEAR_WSS_20MS_WORDS	80		//	64 Kbit/sec WSS 8-bit unsigned linear, 20ms frame size
#define PLAYBACK_8LINEAR_WSS_10MS_WORDS	40		//	64 Kbit/sec WSS 8-bit unsigned linear, 10ms frame size
#define PLAYBACK_G722_WORDS				40		//	64 Kbit/sec G.722, 10ms frame size
#define PLAYBACK_G723_63_WORDS			PLAYBACK_TS63_WORDS	//	6.3 Kbit/sec G.723.1, 30ms frame size
#define PLAYBACK_G723_53_WORDS			PLAYBACK_TS53_WORDS	//	5.3 Kbit/sec G.723.1, 30ms frame size
#define PLAYBACK_G728_10MS_WORDS		16		//	16 Kbit/sec G.728, 10ms frame size
#define PLAYBACK_G728_20MS_WORDS		32		//	16 Kbit/sec G.728, 20ms frame size
#define PLAYBACK_G728_30MS_WORDS		48		//	16 Kbit/sec G.728, 30ms frame size
#define PLAYBACK_G729_10MS_WORDS		6		//	8 Kbit/sec G.729, 10ms frame size
#define PLAYBACK_G729_20MS_WORDS		12		//	8 Kbit/sec G.729, 20ms frame size
#define PLAYBACK_G729_30MS_WORDS		18		//	8 Kbit/sec G.729, 30ms frame size

// Frame sizes in bytes
#define PLAYBACK_FRAME_TS85				(PLAYBACK_TS85_WORDS*2)
#define PLAYBACK_FRAME_TS63				(PLAYBACK_TS63_WORDS*2)
#define PLAYBACK_FRAME_TS53				(PLAYBACK_TS53_WORDS*2)
#define PLAYBACK_FRAME_TS48				(PLAYBACK_TS48_WORDS*2)
#define PLAYBACK_FRAME_TS41				(PLAYBACK_TS41_WORDS*2)
#define PLAYBACK_FRAME_ALAW				(PLAYBACK_ALAW_WORDS*2)
#define PLAYBACK_FRAME_ALAW_30MS		(PLAYBACK_ALAW_30MS_WORDS*2)
#define PLAYBACK_FRAME_ALAW_20MS		(PLAYBACK_ALAW_20MS_WORDS*2)
#define PLAYBACK_FRAME_ALAW_10MS		(PLAYBACK_ALAW_10MS_WORDS*2)
#define PLAYBACK_FRAME_ULAW				(PLAYBACK_ULAW_WORDS*2)
#define PLAYBACK_FRAME_ULAW_30MS		(PLAYBACK_ULAW_30MS_WORDS*2)
#define PLAYBACK_FRAME_ULAW_20MS		(PLAYBACK_ULAW_20MS_WORDS*2)
#define PLAYBACK_FRAME_ULAW_10MS		(PLAYBACK_ULAW_10MS_WORDS*2)
#define PLAYBACK_FRAME_16LINEAR			(PLAYBACK_16LINEAR_WORDS*2)
#define PLAYBACK_FRAME_16LINEAR_30MS	(PLAYBACK_16LINEAR_30MS_WORDS*2)
#define PLAYBACK_FRAME_16LINEAR_20MS	(PLAYBACK_16LINEAR_20MS_WORDS*2)
#define PLAYBACK_FRAME_16LINEAR_10MS	(PLAYBACK_16LINEAR_10MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR			(PLAYBACK_8LINEAR_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_30MS		(PLAYBACK_8LINEAR_30MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_20MS		(PLAYBACK_8LINEAR_20MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_10MS		(PLAYBACK_8LINEAR_10MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_WSS		(PLAYBACK_8LINEAR_WSS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_WSS_30MS	(PLAYBACK_8LINEAR_WSS_30MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_WSS_20MS	(PLAYBACK_8LINEAR_WSS_20MS_WORDS*2)
#define PLAYBACK_FRAME_8LINEAR_WSS_10MS	(PLAYBACK_8LINEAR_WSS_10MS_WORDS*2)
#define PLAYBACK_FRAME_G722				(PLAYBACK_G722_WORDS*2)
#define PLAYBACK_FRAME_G723_63			(PLAYBACK_G723_63_WORDS*2)
#define PLAYBACK_FRAME_G723_53			(PLAYBACK_G723_53_WORDS*2)
#define PLAYBACK_FRAME_G728_10MS		(PLAYBACK_G728_10MS_WORDS*2)
#define PLAYBACK_FRAME_G728_20MS		(PLAYBACK_G728_20MS_WORDS*2)
#define PLAYBACK_FRAME_G728_30MS		(PLAYBACK_G728_30MS_WORDS*2)
#define PLAYBACK_FRAME_G729_10MS		(PLAYBACK_G729_10MS_WORDS*2)
#define PLAYBACK_FRAME_G729_20MS		(PLAYBACK_G729_20MS_WORDS*2)
#define PLAYBACK_FRAME_G729_30MS		(PLAYBACK_G729_30MS_WORDS*2)

#define PLAYBACK_MAX_BUFFER_WORDS	PLAYBACK_16LINEAR_WORDS	//	Max buffer size: Tx or Rx.
#define PLAYBACK_MAX_BUFFER_SIZE	PLAYBACK_FRAME_16LINEAR	//	Max buffer size: Tx or Rx.

#define PLAYBACK_TS85_AVG_RATE	1067	//	TrueSpeech 8.5 Average bytes per second.
#define PLAYBACK_TS63_AVG_RATE	800		//	TrueSpeech 6.3 Average bytes per second.
#define PLAYBACK_TS53_AVG_RATE	667		//	TrueSpeech 5.3 Average bytes per second.
#define PLAYBACK_TS48_AVG_RATE	600		//	TrueSpeech 4.8 Average bytes per second.
#define PLAYBACK_TS41_AVG_RATE	533		//	TrueSpeech 4.1 Average bytes per second.

//==========================================================================
//--------------------------------------------------------------------------
//	Record support
//--------------------------------------------------------------------------
//
//	Additional bit patterns to 'Or' into Command Base 'words'
#define RECORD_TFRMODE_80X5 0	//	Selects Data transfer via Software Control and Status Registers (CT8015/CT8005 protocol mode).
#define RECORD_TFRMODE_8020 3	//	Selects Data transfer via Host Transmit Data Buffer Access Port.

#define RECORD_SYNC_MODE_CODEC 0
#define RECORD_SYNC_MODE_DATA  1
#define RECORD_SYNC_MODE_POLL  2
#define RECORD_SYNC_MODE_HOST  3

//	Automatic Gain Control (AGC)
#define RECORD_AGC_MIN_GAIN     0	//	Sets AGC Min Gain
#define RECORD_AGC_MAX_GAIN     1	//	Sets AGC Max Gain
#define RECORD_AGC_START_GAIN   2	//	Sets AGC Start Gain
#define RECORD_AGC_HOLD_TIME    3	//	Sets AGC Hold Time
#define RECORD_AGC_ATTACK_TIME  4	//	Sets AGC Attack Time Constant
#define RECORD_AGC_DECAY_TIME   5	//	Sets AGC Decay Time Constant
#define RECORD_AGC_ATTACK_THRES 6	//	Sets AGC Attack Threshold
#define RECORD_AGC_ON_OFF       7	//	Sets AGC On/Off. Enable/Disable AGC.

//	AGC Time Contants
#define RECORD_AGC_250_us  0
#define RECORD_AGC_512_us  1
#define RECORD_AGC_1_ms    2
#define RECORD_AGC_2_ms    3
#define RECORD_AGC_4_ms    4
#define RECORD_AGC_8_ms    5
#define RECORD_AGC_16_ms   6
#define RECORD_AGC_32_ms   7
#define RECORD_AGC_64_ms   8
#define RECORD_AGC_128_ms  9
#define RECORD_AGC_256_ms  10
#define RECORD_AGC_512_ms  11
#define RECORD_AGC_1024_ms 12
#define RECORD_AGC_2048_ms 13
#define RECORD_AGC_4096_ms 14
#define RECORD_AGC_8192_ms 15

//	Record modes
#define RECORD_MODE_COMPRESSED		0	//	Selects: Compressed modes, TrueSpeech 8.5-4.1, G.723.1, G.722, G.728, G.729
#define RECORD_MODE_TRUESPEECH		0	//	Selects: TrueSpeech 8.5, 6.3, 5.3, 4.8 or 4.1 Kbps
#define RECORD_MODE_ULAW			4	//	Selects: 64 Kbit/sec Mu-law PCM
#define RECORD_MODE_ALAW			12	//	Selects: 64 Kbit/sec A-law PCM
#define RECORD_MODE_16LINEAR		5	//	Selects: 128 Kbit/sec 16-bit linear
#define RECORD_MODE_8LINEAR			6	//	Selects: 64 Kbit/sec 8-bit signed linear
#define RECORD_MODE_8LINEAR_WSS		7	//	Selects: 64 Kbit/sec WSS 8-bit unsigned linear

//	Record rates
#define RECORD_RATE_TS85	0	//	Selects TrueSpeech 8.5 record rate.
#define RECORD_RATE_TS63	1	//	Selects TrueSpeech 6.3 record rate.
#define RECORD_RATE_TS53	2	//	Selects TrueSpeech 5.3 record rate.
#define RECORD_RATE_TS48	3	//	Selects TrueSpeech 4.8 record rate.
#define RECORD_RATE_TS41	4	//	Selects TrueSpeech 4.1 record rate.
#define RECORD_RATE_G722	7	//	Selects G.722 record rate.
#define RECORD_RATE_G723_63	RECORD_RATE_TS63	//	Selects G.723.1 (6.3 kbps) record rate.
#define RECORD_RATE_G723_53	RECORD_RATE_TS53	//	Selects G.723.1 (5.3 kbps) record rate.
#define RECORD_RATE_G728	5	//	Selects G.728 record rate.
#define RECORD_RATE_G729	6	//	Selects G.729 record rate.

// Frame sizes in WORD units
#define RECORD_TS85_WORDS				16		//	TrueSpeech 8.5, 30ms frame size
#define RECORD_TS63_WORDS				12		//	TrueSpeech 6.3, 30ms frame size
#define RECORD_TS53_WORDS				10		//	TrueSpeech 5.3, 30ms frame size
#define RECORD_TS48_WORDS				9		//	TrueSpeech 4.8, 30ms frame size
#define RECORD_TS41_WORDS				8		//	TrueSpeech 4.1, 30ms frame size
#define RECORD_ALAW_WORDS				120		//	64 Kbit/sec A-law PCM, 30ms frame size
#define RECORD_ALAW_30MS_WORDS			120		//	64 Kbit/sec A-law PCM, 30ms frame size
#define RECORD_ALAW_20MS_WORDS			80		//	64 Kbit/sec A-law PCM, 20ms frame size
#define RECORD_ALAW_10MS_WORDS			40		//	64 Kbit/sec A-law PCM, 10ms frame size
#define RECORD_ULAW_WORDS				120		//	64 Kbit/sec Mu-law PCM, 30ms frame size
#define RECORD_ULAW_30MS_WORDS			120		//	64 Kbit/sec Mu-law PCM, 30ms frame size
#define RECORD_ULAW_20MS_WORDS			80		//	64 Kbit/sec Mu-law PCM, 20ms frame size
#define RECORD_ULAW_10MS_WORDS			40		//	64 Kbit/sec Mu-law PCM, 10ms frame size
#define RECORD_16LINEAR_WORDS			240		//	128 Kbit/sec 16-bit linear, 30ms frame size
#define RECORD_16LINEAR_30MS_WORDS		240		//	128 Kbit/sec 16-bit linear, 30ms frame size
#define RECORD_16LINEAR_20MS_WORDS		160		//	128 Kbit/sec 16-bit linear, 20ms frame size
#define RECORD_16LINEAR_10MS_WORDS		80		//	128 Kbit/sec 16-bit linear, 10ms frame size
#define RECORD_8LINEAR_WORDS			120		//	64 Kbit/sec 8-bit signed linear, 30ms frame size
#define RECORD_8LINEAR_30MS_WORDS		120		//	64 Kbit/sec 8-bit signed linear, 30ms frame size
#define RECORD_8LINEAR_20MS_WORDS		80		//	64 Kbit/sec 8-bit signed linear, 20ms frame size
#define RECORD_8LINEAR_10MS_WORDS		40		//	64 Kbit/sec 8-bit signed linear, 10ms frame size
#define RECORD_8LINEAR_WSS_WORDS		120		//	64 Kbit/sec WSS 8-bit unsigned linear, 30ms frame size
#define RECORD_8LINEAR_WSS_30MS_WORDS	120		//	64 Kbit/sec WSS 8-bit unsigned linear, 30ms frame size
#define RECORD_8LINEAR_WSS_20MS_WORDS	80		//	64 Kbit/sec WSS 8-bit unsigned linear, 20ms frame size
#define RECORD_8LINEAR_WSS_10MS_WORDS	40		//	64 Kbit/sec WSS 8-bit unsigned linear, 10ms frame size
#define RECORD_G722_WORDS				40		//	64 Kbit/sec G.722, 10ms frame size
#define RECORD_G723_63_WORDS			RECORD_TS63_WORDS	//	6.3 Kbit/sec G.723.1, 30ms frame size
#define RECORD_G723_53_WORDS			RECORD_TS53_WORDS	//	5.3 Kbit/sec G.723.1, 30ms frame size
#define RECORD_G728_10MS_WORDS			16		//	16 Kbit/sec G.728, 10ms frame size
#define RECORD_G728_20MS_WORDS			32		//	16 Kbit/sec G.728, 20ms frame size
#define RECORD_G728_30MS_WORDS			48		//	16 Kbit/sec G.728, 30ms frame size
#define RECORD_G729_10MS_WORDS			6		//	8 Kbit/sec G.729, 10ms frame size
#define RECORD_G729_20MS_WORDS			12		//	8 Kbit/sec G.729, 20ms frame size
#define RECORD_G729_30MS_WORDS			18		//	8 Kbit/sec G.729, 30ms frame size

// Frame sizes in bytes
#define RECORD_FRAME_TS85				(RECORD_TS85_WORDS*2)
#define RECORD_FRAME_TS63				(RECORD_TS63_WORDS*2)
#define RECORD_FRAME_TS53				(RECORD_TS53_WORDS*2)
#define RECORD_FRAME_TS48				(RECORD_TS48_WORDS*2)
#define RECORD_FRAME_TS41				(RECORD_TS41_WORDS*2)
#define RECORD_FRAME_ALAW				(RECORD_ALAW_WORDS*2)
#define RECORD_FRAME_ALAW_30MS			(RECORD_ALAW_30MS_WORDS*2)
#define RECORD_FRAME_ALAW_20MS			(RECORD_ALAW_20MS_WORDS*2)
#define RECORD_FRAME_ALAW_10MS			(RECORD_ALAW_10MS_WORDS*2)
#define RECORD_FRAME_ULAW				(RECORD_ULAW_WORDS*2)
#define RECORD_FRAME_ULAW_30MS			(RECORD_ULAW_30MS_WORDS*2)
#define RECORD_FRAME_ULAW_20MS			(RECORD_ULAW_20MS_WORDS*2)
#define RECORD_FRAME_ULAW_10MS			(RECORD_ULAW_10MS_WORDS*2)
#define RECORD_FRAME_16LINEAR			(RECORD_16LINEAR_WORDS*2)
#define RECORD_FRAME_16LINEAR_30MS		(RECORD_16LINEAR_30MS_WORDS*2)
#define RECORD_FRAME_16LINEAR_20MS		(RECORD_16LINEAR_20MS_WORDS*2)
#define RECORD_FRAME_16LINEAR_10MS		(RECORD_16LINEAR_10MS_WORDS*2)
#define RECORD_FRAME_8LINEAR			(RECORD_8LINEAR_WORDS*2)
#define RECORD_FRAME_8LINEAR_30MS		(RECORD_8LINEAR_30MS_WORDS*2)
#define RECORD_FRAME_8LINEAR_20MS		(RECORD_8LINEAR_20MS_WORDS*2)
#define RECORD_FRAME_8LINEAR_10MS		(RECORD_8LINEAR_10MS_WORDS*2)
#define RECORD_FRAME_8LINEAR_WSS		(RECORD_8LINEAR_WSS_WORDS*2)
#define RECORD_FRAME_8LINEAR_WSS_30MS	(RECORD_8LINEAR_WSS_30MS_WORDS*2)
#define RECORD_FRAME_8LINEAR_WSS_20MS	(RECORD_8LINEAR_WSS_20MS_WORDS*2)
#define RECORD_FRAME_8LINEAR_WSS_10MS	(RECORD_8LINEAR_WSS_10MS_WORDS*2)
#define RECORD_FRAME_G722				(RECORD_G722_WORDS*2)
#define RECORD_FRAME_G723_63			(RECORD_G723_63_WORDS*2)
#define RECORD_FRAME_G723_53			(RECORD_G723_53_WORDS*2)
#define RECORD_FRAME_G728_10MS			(RECORD_G728_10MS_WORDS*2)
#define RECORD_FRAME_G728_20MS			(RECORD_G728_20MS_WORDS*2)
#define RECORD_FRAME_G728_30MS			(RECORD_G728_30MS_WORDS*2)
#define RECORD_FRAME_G729_10MS			(RECORD_G729_10MS_WORDS*2)
#define RECORD_FRAME_G729_20MS			(RECORD_G729_20MS_WORDS*2)
#define RECORD_FRAME_G729_30MS			(RECORD_G729_30MS_WORDS*2)

#define RECORD_MAX_BUFFER_WORDS	RECORD_16LINEAR_WORDS	//	Max buffer size: Tx or Rx.
#define RECORD_MAX_BUFFER_SIZE	RECORD_FRAME_16LINEAR	//	Max buffer size: Tx or Rx.

#define RECORD_TS85_AVG_RATE	1067	//	TrueSpeech 8.5 Average bytes per second.
#define RECORD_TS63_AVG_RATE	800		//	TrueSpeech 6.3 Average bytes per second.
#define RECORD_TS53_AVG_RATE	667		//	TrueSpeech 5.3 Average bytes per second.
#define RECORD_TS48_AVG_RATE	600		//	TrueSpeech 4.8 Average bytes per second.
#define RECORD_TS41_AVG_RATE	533		//	TrueSpeech 4.1 Average bytes per second.

//==========================================================================
//--------------------------------------------------------------------------
//	Speakerphone support
//--------------------------------------------------------------------------
//
//	Additional bit patterns to 'Or' into Command Base 'words'
#define SPKRPHONE_LINE_VOLUME_POS_8DB	0	//	+8 dB
#define SPKRPHONE_LINE_VOLUME_POS_4DB	1	//	+4 dB
#define SPKRPHONE_LINE_VOLUME_POS_0DB	2	//	+0 dB
#define SPKRPHONE_LINE_VOLUME_MUTE		3	//	Mute Microphone (also resets AEC)

#define SPKRPHONE_SPEAKER_VOLUME_POS_14DB	0	//	+14 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_12DB	1	//	+12 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_10DB	2	//	+10 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_8DB	3	//	+8 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_6DB	4	//	+6 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_4DB	5	//	+4 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_2DB	6	//	+2 dB
#define SPKRPHONE_SPEAKER_VOLUME_POS_0DB	7	//	0 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_2DB	8	//	-2 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_4DB	9	//	-4 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_6DB	10	//	-6 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_8DB	11	//	-8 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_10DB	12	//	-10 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_12DB	13	//	-12 dB
#define SPKRPHONE_SPEAKER_VOLUME_NEG_14DB	14	//	-14 dB
#define SPKRPHONE_SPEAKER_VOLUME_MUTE		15	//	Mute Speaker

// AEC bit positions
#define SPKRPHONE_AEC_ON	1
#define SPKRPHONE_AEC_LO	2
#define SPKRPHONE_AEC_HI	4

//==========================================================================
//--------------------------------------------------------------------------
//	VxD support
//
//	NOTE: These names will be changed in the future to a generic 'driver'
//        naming convention.
//--------------------------------------------------------------------------
//
// Event bit fields.
#define EVENT_TYPE_INT_DTMF						0x0002
#define EVENT_TYPE_INT_TX_READY					0x0004
#define EVENT_TYPE_INT_RX_READY					0x0008
#define EVENT_TYPE_INT_HOOK						0x0010
#define EVENT_TYPE_INT_RING						0x0020
#define EVENT_TYPE_INT_WRITE_DONE				0x0040
#define EVENT_TYPE_INT_PLAYBACK_VOLUME_CHANGE	0x0080
#define EVENT_TYPE_INT_RECORD_VOLUME_CHANGE		0x0100
#define EVENT_TYPE_INT_ANALOG_SOURCE_CHANGE		0x0200
#define EVENT_TYPE_INT_AEC_CHANGE				0x0400
#define EVENT_TYPE_INT_PLAYBACK_MUTE_CHANGE		0x0800
#define EVENT_TYPE_INT_RECORD_MUTE_CHANGE		0x1000
#define EVENT_TYPE_INT_MIXER_CHANGE				0x2000

//---------------------------------------
//	This is included for legacy support.
//	This name is used by Ring 3 Drivers that use a software interrupt to
//	get the PM entry point to the VxD. If it changes here, all users of this
//	define must recompile.
#define IPJ_VXDNAME		"QTIPJ   "

#define IXJ_DRV_NAME	TEXT("qtxjack.drv")
#define IXJ_INST_NAME	TEXT("Internet PhoneJACK/Internet LineJACK")

// Typedefs

// For IOCTL_VxD_AddPerformanceStat & fnVxD_AddPerformanceStat
typedef struct
{
    DWORD ulFlags;
    LPSTR pszStatName;
    LPSTR pszStatDescription;
    LPVOID pStatFunc;
} PERF_STAT, FAR *LPPERF_STAT;

// Set lpBufPointer to lpPerfStat, dwBufSize to sizeof( PERF_STAT )

/* pStatFunc points either directly to data (always a DWORD for now) */
/* or, if PSTF_FUNCPTR_BIT is set, to a _cdecl function.  This function   */
/* accepts a stat handle as it's argument and returns the stat in eax     */
// The following #defines come from <perf.h>.

#ifndef PSTF_FUNCPTR
#define PSTF_FUNCPTR	0x00000001
#define PSTF_COUNT		0x00000000
#define PSTF_RATE		0x00000002
#endif

typedef struct ipj_vxd_devio
{
    DWORD	dwSize;
	DEVNODE	dnDevNode;
	DWORD	dwFunctionCode;
    DWORD	dwReturn;
	DWORD	dwSetData;
	DWORD	dwBufSize;
	LPVOID	lpBufPointer;
	DWORD	dwOutBufSize;
	LPVOID	lpOutBufPointer;
    DWORD	dwReserved;	// Must be zero
} IPJ_VXD_DEVIO;

#endif

//	eof: ixjDefs.h
