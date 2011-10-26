/*
 * videoio.cxx
 *
 * Classes to support streaming video input (grabbing) and output.
 *
 * Portable Windows Library
 *
 * Copyright (c) 1993-2000 Equivalence Pty. Ltd.
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): Mark Cooke (mpc@star.sr.bham.ac.uk)
 *
 * $Log: videoio.cxx,v $
 * Revision 1.58.2.3  2006/12/30 21:48:54  dsandras
 * Backported patch from HEAD that fixes Ekiga bug #333311.
 *
 * Revision 1.58.2.2  2006/03/07 20:55:28  dsandras
 * More backports from HEAD.
 *
 * Revision 1.60  2006/03/07 20:53:51  dsandras
 * Added support for JPEG based webcams, thanks to Luc Saillard <luc saillard org>.
 *
 * Revision 1.58.2.1  2006/01/30 00:03:12  csoutheren
 * Backported support for cameras that return MJPEG streams
 * Thanks to Luc Saillard and Damien Sandras
 *
 * Revision 1.59  2006/01/29 22:46:39  csoutheren
 * Added support for cameras that return MJPEG streams
 * Thanks to Luc Saillard and Damien Sandras
 *
 * Revision 1.58  2006/01/09 18:19:13  dsandras
 * Add YUY2 (or YUV420) format. Resizing to YUV420P is done, but it's not very
 * efficient.
 * Fix the gray border when doing padding for YUV420P (change it to black).
 * Logitech webcam fusion export only big format in yuy2.
 * Patches provided by Luc Saillard <luc _AT____ saillard.org>. Many thanks!
 *
 * Revision 1.57  2005/11/30 12:47:42  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.56  2005/09/06 12:41:22  rjongbloed
 * Fixed correct creation (or non creation) of converter when using SetFrameSizeConverter()
 *
 * Revision 1.55  2005/08/23 12:42:23  rjongbloed
 * Fixed problems with negative hight native flipping not working with all sizes.
 *
 * Revision 1.54  2005/08/09 09:08:12  rjongbloed
 * Merged new video code from branch back to the trunk.
 *
 * Revision 1.53.6.2  2005/07/17 12:17:41  rjongbloed
 * Fixed deadlock changing size
 *
 * Revision 1.53.6.1  2005/07/17 09:27:08  rjongbloed
 * Major revisions of the PWLib video subsystem including:
 *   removal of F suffix on colour formats for vertical flipping, all done with existing bool
 *   working through use of RGB and BGR formats so now consistent
 *   cleaning up the plug in system to use virtuals instead of pointers to functions.
 *   rewrite of SDL to be a plug in compatible video output device.
 *   extensive enhancement of video test program
 *
 * Revision 1.53  2005/01/04 08:09:42  csoutheren
 * Fixed Linux configure problems
 *
 * Revision 1.52  2004/11/17 10:13:14  csoutheren
 * Fixed compilation with gcc 4.0.0
 *
 * Revision 1.51  2004/10/27 09:24:18  dsandras
 * Added patch from Nicola Orru' to convert from SBGGR8 to YUV420P. Thanks!
 *
 * Revision 1.50  2004/10/23 10:54:39  ykiryanov
 * Added ifdef _WIN32_WCE for PocketPC 2003 SDK port
 *
 * Revision 1.49  2004/08/16 06:40:59  csoutheren
 * Added adapters template to make device plugins available via the abstract factory interface
 *
 * Revision 1.48  2004/04/18 12:49:22  csoutheren
 * Patches to video code thanks to Guilhem Tardy (hope I get it right this time :)
 *
 * Revision 1.47  2004/04/03 23:53:10  csoutheren
 * Added various changes to improce compatibility with the Sun Forte compiler
 *   Thanks to Brian Cameron
 * Added detection of readdir_r version
 *
 * Revision 1.46  2004/01/18 14:25:58  dereksmithies
 * New methods to make the opening of video input devices easier.
 *
 * Revision 1.45  2004/01/17 17:41:50  csoutheren
 * Changed to use PString::MakeEmpty
 *
 * Revision 1.44  2003/12/14 10:01:02  rjongbloed
 * Resolved issue with name space conflict os static and virtual forms of GetDeviceNames() function.
 *
 * Revision 1.43  2003/11/23 22:17:35  dsandras
 * Added YUV420P to BGR24 and BGR32 conversion.
 *
 * Revision 1.42  2003/11/19 04:30:15  csoutheren
 * Changed to support video output plugins
 *
 * Revision 1.41  2003/11/18 10:40:51  csoutheren
 * Added pragma implementation to fix vtable link problems
 *
 * Revision 1.40  2003/11/18 06:46:38  csoutheren
 * Changed to support video input plugins
 *
 * Revision 1.39  2003/05/14 07:51:23  rjongbloed
 * Changed SetColourFormatConverter so if converter already in place no
 *   change is made.
 * Fixed some trace logs.
 *
 * Revision 1.38  2003/04/03 23:21:34  robertj
 * Added reversed RGB byte order versions (BGR24), thanks Damien Sandras
 *
 * Revision 1.37  2003/03/21 04:09:33  robertj
 * Changed PPM video output device so you can specify the full format of the
 *   output file uinng printf command for the frame number eg %u or %03i or
 *   something. If there is no %u in the Opan() argument, a %u is added after
 *   the filename.
 * Fixed video output RGB SetFrameData so abide by correct semantics. The input
 *   is aways to be what was set using SetColourFormat() or
 *   SetColourFormatConverter().
 *
 * Revision 1.36  2003/03/20 23:42:01  dereks
 * Make PPM video output device work correctly.
 *
 * Revision 1.35  2003/03/17 07:50:41  robertj
 * Added OpenFull() function to open with all video parameters in one go.
 * Made sure vflip variable is set in converter even if converter has not
 *   been set yet, should not depend on the order of functions!
 * Removed canCaptureVideo variable as this is really a virtual function to
 *   distinguish PVideoOutputDevice from PVideoInputDevice, it is not dynamic.
 * Made significant enhancements to PVideoOutputDevice class.
 * Added PVideoOutputDevice descendants for NULL and PPM files.
 *
 * Revision 1.34  2002/09/01 23:25:26  dereks
 * Documentation fix from Walter Whitlock. Many thanks.
 *
 * Revision 1.33  2002/09/01 22:38:21  dereks
 * Remove previous clarification, cause it breaks openphone code.
 *
 * Revision 1.32  2002/08/30 02:31:43  dereks
 * Make operation of the code more clear. Thanks Diego Tartara
 *
 * Revision 1.31  2002/04/12 08:24:53  robertj
 * Added text string output for tracing video format.
 *
 * Revision 1.30  2002/04/07 22:49:32  rogerh
 * Add some comments
 *
 * Revision 1.29  2002/04/05 06:41:54  rogerh
 * Apply video changes from Damien Sandras <dsandras@seconix.com>.
 * The Video Channel and Format are no longer set in Open(). Instead
 * call the new SetVideoChannelFormat() method. This makes video capture
 * and GnomeMeeting more stable with certain Linux video capture devices.
 *
 * Revision 1.28  2002/02/20 02:37:26  dereks
 * Initial release of Firewire camera support for linux.
 * Many thanks to Ryutaroh Matsumoto <ryutaroh@rmatsumoto.org>.
 *
 * Revision 1.27  2002/01/17 20:20:46  dereks
 * Adjust PVideoInputDevice::SetVFlipState to cope better when a converter class is
 * not attached.   Thanks  Walter Whitlock.
 *
 * Revision 1.26  2002/01/16 07:51:16  robertj
 * MSVC compatibilty changes
 *
 * Revision 1.25  2002/01/14 02:59:41  robertj
 * Added preferred colour format selection, thanks Walter Whitlock
 *
 * Revision 1.24  2002/01/08 01:32:20  robertj
 * Tidied up some PTRACE debug output.
 *
 * Revision 1.23  2002/01/04 04:11:45  dereks
 * Add video flip code from Walter Whitlock, which flips code at the grabber.
 *
 * Revision 1.22  2001/12/10 22:23:43  dereks
 * Enable resize of CIF source image into QCIF size.
 *
 * Revision 1.21  2001/12/06 22:15:09  dereks
 * Additional debugging lines
 *
 * Revision 1.20  2001/11/28 04:45:14  robertj
 * Added Win32 flipped RGB colour formats.
 *
 * Revision 1.19  2001/11/28 00:07:32  dereks
 * Locking added to PVideoChannel, allowing reader/writer to be changed mid call
 * Enabled adjustment of the video frame rate
 * New fictitous image, a blank grey area
 *
 * Revision 1.18  2001/09/25 04:25:38  dereks
 * Add fix from Stelian Pop to improve the field of view  for
 * the  small image with a  Sony Vaio Motion Eye. Many thanks.
 *
 * Revision 1.17  2001/08/03 04:21:51  dereks
 * Add colour/size conversion for YUV422->YUV411P
 * Add Get/Set Brightness,Contrast,Hue,Colour for PVideoDevice,  and
 * Linux PVideoInputDevice.
 * Add lots of PTRACE statement for debugging colour conversion.
 * Add support for Sony Vaio laptop under linux. Requires 2.4.7 kernel.
 *
 * Revision 1.16  2001/06/27 17:23:33  rogerh
 * Back out my previous change
 *
 * Revision 1.15  2001/06/26 15:48:31  rogerh
 * Do not call GetInputDeviceName if there is no video grabber code
 *
 * Revision 1.14  2001/05/22 23:38:45  robertj
 * Fixed bug in PVideoOutputDevice, removed redundent SetFrameSize.
 *
 * Revision 1.13  2001/03/20 02:21:57  robertj
 * More enhancements from Mark Cooke
 *
 * Revision 1.12  2001/03/08 08:31:34  robertj
 * Numerous enhancements to the video grabbing code including resizing
 *   infrastructure to converters. Thanks a LOT, Mark Cooke.
 *
 * Revision 1.11  2001/03/08 02:18:45  robertj
 * Added improved defaulting of video formats so Open() does not fail.
 * Removed the requirement that the device be open before you can set
 *   formats such as colour, video, channel number etc.
 *
 * Revision 1.10  2001/03/07 01:41:03  dereks
 * Fix memory leak, on destroying PVideoDevice
 * Ensure converter class is resized correctly.
 *
 * Revision 1.9  2001/03/06 23:34:20  robertj
 * Added static function to get input device names.
 * Moved some inline virtuals to non-inline.
 *
 * Revision 1.8  2001/03/05 01:12:41  robertj
 * Added more source formats for conversion, use list. Thanks Mark Cooke.
 *
 * Revision 1.7  2001/03/03 05:06:31  robertj
 * Major upgrade of video conversion and grabbing classes.
 *
 * Revision 1.6  2000/12/19 22:20:26  dereks
 * Add video channel classes to connect to the PwLib PVideoInputDevice class.
 * Add PFakeVideoInput class to generate test images for video.
 *
 * Revision 1.5  2000/11/09 00:20:58  robertj
 * Added qcif size constants
 *
 * Revision 1.4  2000/07/26 03:50:50  robertj
 * Added last error variable to video device.
 *
 * Revision 1.3  2000/07/26 02:13:48  robertj
 * Added some more "common" bounds checking to video device.
 *
 * Revision 1.2  2000/07/25 13:38:26  robertj
 * Added frame rate parameter to video frame grabber.
 *
 * Revision 1.1  2000/07/15 09:47:35  robertj
 * Added video I/O device classes.
 *
 */

#ifndef _WIN32_WCE
#pragma implementation "videoio.h"
#endif // !_WIN32_WCE 

#include <ptlib.h>
#include <ptlib/videoio.h>
#include <ptlib/vconvert.h>

namespace PWLibStupidWindowsHacks {
  int loadVideoStuff;
};

namespace PWLib {
  PFactory<PDevicePluginAdapterBase>::Worker< PDevicePluginAdapter<PVideoInputDevice> > vidinChannelFactoryAdapter("PVideoInputDevice", TRUE);
  PFactory<PDevicePluginAdapterBase>::Worker< PDevicePluginAdapter<PVideoOutputDevice> > vidoutChannelFactoryAdapter("PVideoOutputDevice", TRUE);
};

template <> PVideoInputDevice * PDevicePluginFactory<PVideoInputDevice>::Worker::Create(const PString & type) const
{
  return PVideoInputDevice::CreateDevice(type);
}

template <> PVideoOutputDevice * PDevicePluginFactory<PVideoOutputDevice>::Worker::Create(const PString & type) const
{
  return PVideoOutputDevice::CreateDevice(type);
}

///////////////////////////////////////////////////////////////////////////////

#if PTRACING
ostream & operator<<(ostream & strm, PVideoDevice::VideoFormat fmt)
{
  static const char * const VideoFormatNames[PVideoDevice::NumVideoFormats] = {
    "PAL",
    "NTSC",
    "SECAM",
    "Auto"
  };

  if (fmt < PVideoDevice::NumVideoFormats && VideoFormatNames[fmt] != NULL)
    strm << VideoFormatNames[fmt];
  else
    strm << "VideoFormat<" << (unsigned)fmt << '>';

  return strm;
}
#endif

///////////////////////////////////////////////////////////////////////////////
// PVideoDevice

PVideoDevice::PVideoDevice()
{
  lastError = 0;

  videoFormat = Auto;
  channelNumber = -1;  // -1 will find the first working channel number.
  frameWidth = CIFWidth;
  frameHeight = CIFHeight;
  nativeVerticalFlip = FALSE;

  converter = NULL;

  SetFrameRate(0);
}

PVideoDevice::~PVideoDevice()
{
  if (converter)
    delete converter;
}


BOOL PVideoDevice::OpenFull(const OpenArgs & args, BOOL startImmediate)
{
  if (args.deviceName[0] == '#') {
    PStringArray devices = GetDeviceNames();
    PINDEX id = args.deviceName.Mid(1).AsUnsigned();
    if (id == 0 || id > devices.GetSize())
      return FALSE;

    if (!Open(devices[id-1], FALSE))
      return FALSE;
  }
  else {
    if (!Open(args.deviceName, FALSE))
      return FALSE;
  }

  if (!SetVideoFormat(args.videoFormat))
    return FALSE;

  if (!SetChannel(args.channelNumber))
    return FALSE;

  if (args.convertFormat) {
    if (!SetColourFormatConverter(args.colourFormat))
      return FALSE;
  }
  else {
    if (!SetColourFormat(args.colourFormat))
      return FALSE;
  }

  if (args.rate > 0) {
    if (!SetFrameRate(args.rate))
      return FALSE;
  }

  if (args.convertSize) {
    if (!SetFrameSizeConverter(args.width, args.height, args.scaleSize))
      return FALSE;
  }
  else {
    if (!SetFrameSize(args.width, args.height))
      return FALSE;
  }

  if (!SetVFlipState(args.flip))
    return FALSE;

  if (args.brightness >= 0) {
    if (!SetBrightness(args.brightness))
      return FALSE;
  }

  if (args.whiteness >= 0) {
    if (!SetWhiteness(args.whiteness))
      return FALSE;
  }

  if (args.contrast >= 0) {
    if (!SetContrast(args.contrast))
      return FALSE;
  }

  if (args.colour >= 0) {
    if (!SetColour(args.colour))
      return FALSE;
  }

  if (args.hue >= 0) {
    if (!SetColour(args.hue))
      return FALSE;
  }

  if (startImmediate)
    return Start();

  return TRUE;
}


BOOL PVideoDevice::Close()
{
  return TRUE;  
}


BOOL PVideoDevice::Start()
{
  return TRUE;
}


BOOL PVideoDevice::Stop()
{
  return TRUE;
}


BOOL PVideoDevice::SetVideoFormat(VideoFormat videoFmt)
{
  videoFormat = videoFmt;
  return TRUE;
}


PVideoDevice::VideoFormat PVideoDevice::GetVideoFormat() const
{
  return videoFormat;
}


int PVideoDevice::GetNumChannels()
{
  return 1;
}


BOOL PVideoDevice::SetChannel(int channelNum)
{
  if (channelNum < 0) { // Seek out the first available channel
    for (int c = 0; c < GetNumChannels(); c++) {
      if (SetChannel(c))
        return TRUE;
    }
    return FALSE;
  }

  if (channelNum >= GetNumChannels())
    return FALSE;

  channelNumber = channelNum;
  return TRUE;
}


int PVideoDevice::GetChannel() const
{
  return channelNumber;
}


//Colour format bit per pixel table.
// These are in rough order of colour gamut size
static struct {
  const char * colourFormat;
  unsigned     bitsPerPixel;
} colourFormatBPPTab[] = {
  { "RGB32",   32 },
  { "BGR32",   32 },
  { "RGB24",   24 },
  { "BGR24",   24 },
  { "MJPEG",   16 },
  { "JPEG",    16 },
  { "YUY2",    16 },
  { "YUV422",  16 },
  { "YUV422P", 16 },
  { "YUV411",  12 },
  { "YUV411P", 12 },
  { "RGB565",  16 },
  { "RGB555",  16 },
  { "YUV420",  12 },
  { "YUV420P", 12 },
  { "IYUV",    12 },
  { "I420",    12 },
  { "YUV410",  10 },
  { "YUV410P", 10 },
  { "Grey",     8 },
  { "GreyF",    8 },
  { "UYVY422", 16 },
  { "UYV444",  24 },
  { "SBGGR8",   8 }
};


BOOL PVideoDevice::SetColourFormatConverter(const PString & colourFmt)
{
  if (converter != NULL) {
    if (CanCaptureVideo()) {
      if (converter->GetDstColourFormat() == colourFmt)
        return TRUE;
    }
    else {
      if (converter->GetSrcColourFormat() == colourFmt)
        return TRUE;
    }
    delete converter;
    converter = NULL;
  }
  
  if (!preferredColourFormat.IsEmpty()) {
    PTRACE(4,"PVidDev\tSetColourFormatConverter, want " << colourFmt << " trying " << preferredColourFormat);
    if (SetColourFormat(preferredColourFormat)) {
      if (CanCaptureVideo()) {
        PTRACE(4,"PVidDev\tSetColourFormatConverter set camera to native "<< preferredColourFormat);
        if (preferredColourFormat != colourFmt)
          converter = PColourConverter::Create(preferredColourFormat, colourFmt, frameWidth, frameHeight);
      }
      else {
        PTRACE(4,"PVidDev\tSetColourFormatConverter set renderer to "<< preferredColourFormat);
        if (preferredColourFormat != colourFmt)
          converter = PColourConverter::Create(colourFmt, preferredColourFormat, frameWidth, frameHeight);
      }

      if (nativeVerticalFlip && converter == NULL)
          converter = PColourConverter::Create(colourFmt, colourFmt, frameWidth, frameHeight);

      if (converter != NULL) {
        converter->SetVFlipState(nativeVerticalFlip);
        return TRUE;
      } 
    }
  }
  
  if (SetColourFormat(colourFmt)) {
    if (nativeVerticalFlip) {
      converter = PColourConverter::Create(colourFmt, colourFmt, frameWidth, frameHeight);
      if (PAssertNULL(converter) == NULL)
        return FALSE;
      converter->SetVFlipState(nativeVerticalFlip);
    }

    PTRACE(3, "PVidDev\tSetColourFormatConverter success for native " << colourFmt);    
    return TRUE;
  }
  
  /************************
    Eventually, need something more sophisticated than this, but for the
    moment pick the known colour formats that the device is very likely to
    support and then look for a conversion routine from that to the
    destination format.

    What we really want is some sort of better heuristic that looks at
    computational requirements of each converter and picks a pair of formats
    that the hardware supports and uses the least CPU.
  */

  PINDEX knownFormatIdx = 0;
  while (knownFormatIdx < PARRAYSIZE(colourFormatBPPTab)) {
    PString formatToTry = colourFormatBPPTab[knownFormatIdx].colourFormat;
    PTRACE(4,"PVidDev\tSetColourFormatConverter, want " << colourFmt << " trying " << formatToTry);
    if (SetColourFormat(formatToTry)) {
      if (CanCaptureVideo()) {
        PTRACE(4,"PVidDev\tSetColourFormatConverter set camera to "<< formatToTry);
        converter = PColourConverter::Create(formatToTry, colourFmt, frameWidth, frameHeight);
      }
      else {
        PTRACE(4,"PVidDev\tSetColourFormatConverter set renderer to "<< formatToTry);
        converter = PColourConverter::Create(colourFmt, formatToTry, frameWidth, frameHeight);
      }
      if (converter != NULL) {
        // set converter properties that depend on this color format
        PTRACE(3, "PVidDev\tSetColourFormatConverter succeeded for " << colourFmt << " and device using " << formatToTry);
        converter->SetVFlipState(nativeVerticalFlip);
        return TRUE;
      } 
    } 
    knownFormatIdx++;
  }

  PTRACE(2, "PVidDev\tSetColourFormatConverter  FAILED for " << colourFmt);
  return FALSE;
}


BOOL PVideoDevice::SetColourFormat(const PString & colourFmt)
{
  if (!colourFmt) {
    colourFormat = colourFmt.ToUpper();
    return TRUE;
  }

  for (PINDEX i = 0; i < PARRAYSIZE(colourFormatBPPTab); i++) {
    if (SetColourFormat(colourFormatBPPTab[i].colourFormat))
      return TRUE;
  }

  return FALSE;
}


const PString & PVideoDevice::GetColourFormat() const
{
  return colourFormat;
}


BOOL PVideoDevice::SetFrameRate(unsigned rate)
{

  if (rate < 1) {
    frameRate = 0;
    return TRUE;
  }

  frameRate = rate;
  previousFrameTime = PTime();
  msBetweenFrames = 1000/rate;
  frameTimeError  = 0;

  return TRUE;
}


BOOL PVideoDevice::GetVFlipState()
{
  if (converter != NULL)
    return converter->GetVFlipState() ^ nativeVerticalFlip;

  return nativeVerticalFlip;
}


BOOL PVideoDevice::SetVFlipState(BOOL newVFlip)
{
  if (newVFlip && converter == NULL)
    converter = PColourConverter::Create(colourFormat, colourFormat, frameWidth, frameHeight);

  if (converter != NULL)
    converter->SetVFlipState(newVFlip ^ nativeVerticalFlip);

  return TRUE;
}


unsigned PVideoDevice::GetFrameRate() const
{
  return frameRate;
}


BOOL PVideoDevice::GetFrameSizeLimits(unsigned & minWidth,
                                      unsigned & minHeight,
                                      unsigned & maxWidth,
                                      unsigned & maxHeight) 
{
  minWidth = minHeight = 1;
  maxWidth = maxHeight = UINT_MAX;
  return FALSE;
}


static struct {
    unsigned asked_width, asked_height, device_width, device_height;
} framesizeTab[] = {    
    { 704, 576,    640, 480 },
    { 640, 480,    704, 576 },
    { 640, 480,    352, 288 },

    { 352, 288,    704, 576 },
    { 352, 288,    640, 480 },
    { 352, 288,    352, 240 },
    { 352, 288,    320, 240 },
    { 352, 288,    176, 144 },
    { 352, 288,   1024, 576 }, /* High resolution need to be set at the end */
    { 352, 288,   1280, 960 },

    { 352, 240,    352, 288 },
    { 352, 240,    320, 240 },
    { 352, 240,    640, 480 }, 

    { 320, 240,    352, 288 },
    { 320, 240,    352, 240 },
    { 320, 240,    640, 480 }, 

    { 176, 144,    352, 288 },
    { 176, 144,    352, 240 },
    { 176, 144,    320, 240 },
    { 176, 144,    176, 120 },
    { 176, 144,    160, 120 },
    { 176, 144,    640, 480 }, 
    { 176, 144,   1024, 576 }, 
    { 176, 144,   1280, 960 }, /* High resolution need to be set at the end */

    { 176, 120,    352, 288 },
    { 176, 120,    352, 240 },
    { 176, 120,    320, 240 },
    { 176, 120,    176, 144 },
    { 176, 120,    160, 120 },
    { 176, 120,    640, 480 }, 

    { 160, 120,    352, 288 },
    { 160, 120,    352, 240 },
    { 160, 120,    320, 240 },
    { 160, 120,    176, 144 },
    { 160, 120,    176, 120 },
    { 160, 120,    640, 480 }, 
};

BOOL PVideoDevice::SetFrameSizeConverter(unsigned width, unsigned height,
           BOOL bScaleNotCrop)
{
  if (SetFrameSize(width, height)) {
    if (nativeVerticalFlip && converter == NULL) {
      converter = PColourConverter::Create(colourFormat, colourFormat, frameWidth, frameHeight);
      if (PAssertNULL(converter) == NULL)
        return FALSE;
    }
    if (converter != NULL) {
      converter->SetFrameSize(frameWidth, frameHeight);
      converter->SetVFlipState(nativeVerticalFlip);
    }
    return TRUE;
  }

  if (converter == NULL) {
    converter = PColourConverter::Create(colourFormat, colourFormat, width, height);
    if (converter == NULL) {
      PTRACE(1, "PVidDev\tSetFrameSizeConverter Colour converter creation failed");
      return FALSE;
    }
  }
  
  PTRACE(3,"PVidDev\tColour converter used for " << width << 'x' << height);

  unsigned minWidth, minHeight, maxWidth, maxHeight;
  BOOL limits = GetFrameSizeLimits(minWidth, minHeight, maxWidth, maxHeight);

  for (PINDEX i = 0; i < PARRAYSIZE(framesizeTab); i++) {
    if (framesizeTab[i].asked_width == width &&
        framesizeTab[i].asked_height == height &&
        (!limits ||
         (framesizeTab[i].device_width >= minWidth &&
          framesizeTab[i].device_width <= maxWidth &&
          framesizeTab[i].device_height >= minHeight &&
          framesizeTab[i].device_height <= maxHeight)) &&
          SetFrameSize(framesizeTab[i].device_width,
          framesizeTab[i].device_height)) {
      if (CanCaptureVideo() ?
          converter->SetDstFrameSize(width, height, bScaleNotCrop)
          :
          converter->SetSrcFrameSize(width, height) &&
          converter->SetDstFrameSize(framesizeTab[i].device_width,
          framesizeTab[i].device_height,
          bScaleNotCrop)) {
        PTRACE(4,"PVideoDevice\tSetFrameSizeConverter succeeded for converting from "
            << framesizeTab[i].device_width << 'x' << framesizeTab[i].device_height
         << " to " << width << 'x' << height);

        converter->SetVFlipState(converter->GetVFlipState() ^ nativeVerticalFlip);
        return TRUE;
      }
    }
  }

  if (CanCaptureVideo()) {
    // Failed to find a resolution the device can do so far, so try
    // using the maximum width and height it claims it can do.
    if (limits &&
      SetFrameSize(maxWidth, maxHeight)) {
      if (converter->SetDstFrameSize(width, height, bScaleNotCrop)) {
        PTRACE(4,"PVideoDevice\tSetFrameSizeConverter succeeded for converting from "
          << maxWidth << 'x' << maxHeight
          << " to " << width << 'x' << height);

        converter->SetVFlipState(converter->GetVFlipState() ^ nativeVerticalFlip);
        return TRUE;
      }
    }
  }

  PTRACE(2,"PVideoDevice\tSetFrameSizeConverter failed for " << width << 'x' << height);

  return FALSE;
}


BOOL PVideoDevice::SetFrameSize(unsigned width, unsigned height)
{
#if PTRACING
  unsigned oldWidth = frameWidth;
  unsigned oldHeight = frameHeight;
#endif

  unsigned minWidth, minHeight, maxWidth, maxHeight;
  GetFrameSizeLimits(minWidth, minHeight, maxWidth, maxHeight);

  if (width < minWidth)
    frameWidth = minWidth;
  else if (width > maxWidth)
    frameWidth = maxWidth;
  else
    frameWidth = width;

  if (height < minHeight)
    frameHeight = minHeight;
  else if (height > maxHeight)
    frameHeight = maxHeight;
  else
    frameHeight = height;

  if (converter != NULL) {
    if (!converter->SetSrcFrameSize(width, height) ||
        !converter->SetDstFrameSize(width, height, FALSE)) {
      PTRACE(1, "PVidDev\tSetFrameSize with converter failed with " << width << 'x' << height);
      return FALSE;
    }
  }

  PTRACE_IF(2, oldWidth != frameWidth || oldHeight != frameHeight,
            "PVidDev\tSetFrameSize to " << frameWidth << 'x' << frameHeight);
  return TRUE;
}


BOOL PVideoDevice::GetFrameSize(unsigned & width, unsigned & height) 
{
#if 1
  // Channels get very upset at this not returning the output size.
  if (converter)
    return converter->GetDstFrameSize(width, height);
#endif
  width = frameWidth;
  height = frameHeight;
  return TRUE;
}


unsigned PVideoDevice::GetFrameWidth() const
{
#if 1
    unsigned w,h;

    // Channels get very upset at this not returning the output size.
    if (converter) {
      converter->GetDstFrameSize(w, h);
      return w;
    }
#endif
  return frameWidth;
}


unsigned PVideoDevice::GetFrameHeight() const
{
#if 1
    unsigned w,h;

    // Channels get very upset at this not returning the output size.
    if (converter) {
      converter->GetDstFrameSize(w, h);
      return h;
    }
#endif
  return frameHeight;
}


unsigned PVideoDevice::CalculateFrameBytes(unsigned width, unsigned height,
                                           const PString & colourFormat)
{
  for (PINDEX i = 0; i < PARRAYSIZE(colourFormatBPPTab); i++) {
    if (colourFormat *= colourFormatBPPTab[i].colourFormat)
      return width * height * colourFormatBPPTab[i].bitsPerPixel/8;
  }
  return 0;
}
 

PINDEX PVideoDevice::GetMaxFrameBytesConverted(PINDEX rawFrameBytes) const
{
  if (converter == NULL)
    return rawFrameBytes;

  PINDEX srcFrameBytes = converter->GetMaxSrcFrameBytes();
  PINDEX dstFrameBytes = converter->GetMaxDstFrameBytes();
  PINDEX convertedFrameBytes = PMAX(srcFrameBytes, dstFrameBytes);
  return PMAX(rawFrameBytes, convertedFrameBytes);
}


int PVideoDevice::GetBrightness()
{
  return frameBrightness;
}


BOOL PVideoDevice::SetBrightness(unsigned newBrightness)
{
  frameBrightness = newBrightness;
  return TRUE;
}


int PVideoDevice::GetWhiteness()
{
  return frameWhiteness;
}


BOOL PVideoDevice::SetWhiteness(unsigned newWhiteness)
{
  frameWhiteness = newWhiteness;
  return TRUE;
}


int PVideoDevice::GetColour()
{
  return frameColour;
}


BOOL PVideoDevice::SetColour(unsigned newColour)
{
  frameColour=newColour;
  return TRUE;
}


int PVideoDevice::GetContrast()
{
  return frameContrast;
}


BOOL PVideoDevice::SetContrast(unsigned newContrast)
{
  frameContrast=newContrast;
  return TRUE;
}


int PVideoDevice::GetHue()
{
  return frameHue;
}


BOOL PVideoDevice::SetHue(unsigned newHue)
{
  frameHue=newHue;
  return TRUE;
}

    
BOOL PVideoDevice::GetParameters (int *whiteness,
                                  int *brightness, 
                                  int *colour,
                                  int *contrast,
                                  int *hue)
{
  if (!IsOpen())
    return FALSE;

  *brightness = frameBrightness;
  *colour     = frameColour;
  *contrast   = frameContrast;
  *hue        = frameHue;
  *whiteness  = frameWhiteness;

  return TRUE;
}

BOOL PVideoDevice::SetVideoChannelFormat (int newNumber, VideoFormat newFormat) 
{
  BOOL err1, err2;

  err1 = SetChannel (newNumber);
  err2 = SetVideoFormat (newFormat);
  
  return (err1 && err2);
}

PStringList PVideoDevice::GetDeviceNames() const
{
  return PStringList();
}


///////////////////////////////////////////////////////////////////////////////
// PVideoOutputDevice

PVideoOutputDevice::PVideoOutputDevice()
{
}


BOOL PVideoOutputDevice::CanCaptureVideo() const
{
  return FALSE;
}


///////////////////////////////////////////////////////////////////////////////
// PVideoOutputDeviceRGB

PVideoOutputDeviceRGB::PVideoOutputDeviceRGB()
{
  PTRACE(6, "RGB\t Constructor of PVideoOutputDeviceRGB");

  colourFormat = "RGB24";
  bytesPerPixel = 3;
  swappedRedAndBlue = false;
  SetFrameSize(frameWidth, frameHeight);
}


BOOL PVideoOutputDeviceRGB::SetColourFormat(const PString & colourFormat)
{
  PWaitAndSignal m(mutex);

  PINDEX newBytesPerPixel;
  bool newSwappedRedAndBlue;
  if (colourFormat *= "RGB32") {
    newBytesPerPixel = 4;
    newSwappedRedAndBlue = false;
  }
  else if (colourFormat *= "RGB24") {
    newBytesPerPixel = 3;
    newSwappedRedAndBlue = false;
  }
  else if (colourFormat *= "BGR32") {
    newBytesPerPixel = 4;
    newSwappedRedAndBlue = true;
  }
  else if (colourFormat *= "BGR24") {
    newBytesPerPixel = 3;
    newSwappedRedAndBlue = true;
  }
  else
    return FALSE;

  if (!PVideoOutputDevice::SetColourFormat(colourFormat))
    return FALSE;

  bytesPerPixel = newBytesPerPixel;
  scanLineWidth = ((frameWidth*bytesPerPixel+3)/4)*4;
  return frameStore.SetSize(frameHeight*scanLineWidth);
}


BOOL PVideoOutputDeviceRGB::SetFrameSize(unsigned width, unsigned height)
{
  PWaitAndSignal m(mutex);

  if (!PVideoOutputDevice::SetFrameSize(width, height))
    return FALSE;

  scanLineWidth = ((frameWidth*bytesPerPixel+3)/4)*4;
  return frameStore.SetSize(frameHeight*scanLineWidth);
}


PINDEX PVideoOutputDeviceRGB::GetMaxFrameBytes()
{
  PWaitAndSignal m(mutex);
  return GetMaxFrameBytesConverted(frameStore.GetSize());
}


BOOL PVideoOutputDeviceRGB::SetFrameData(unsigned x, unsigned y,
                                         unsigned width, unsigned height,
                                         const BYTE * data,
                                         BOOL endFrame)
{
  PWaitAndSignal m(mutex);

  if (x+width > frameWidth || y+height > frameHeight)
    return FALSE;

  if (x == 0 && width == frameWidth && y == 0 && height == frameHeight) {
    if (converter != NULL)
      converter->Convert(data, frameStore.GetPointer());
    else
      memcpy(frameStore.GetPointer(), data, height*scanLineWidth);
  }
  else {
    if (converter != NULL) {
      PAssertAlways("Converted output of partial RGB frame not supported");
      return FALSE;
    }

    if (x == 0 && width == frameWidth)
      memcpy(frameStore.GetPointer() + y*scanLineWidth, data, height*scanLineWidth);
    else {
      for (unsigned dy = 0; dy < height; dy++)
        memcpy(frameStore.GetPointer() + (y+dy)*scanLineWidth + x*bytesPerPixel,
               data + dy*width*bytesPerPixel, width*bytesPerPixel);
    }
  }

  if (endFrame)
    return FrameComplete();

  return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
// PVideoOutputDevicePPM

#ifdef SHOULD_BE_MOVED_TO_PLUGIN

PVideoOutputDevicePPM::PVideoOutputDevicePPM()
{
  PTRACE(6, "PPM\t Constructor of PVideoOutputDevicePPM");
  frameNumber = 0;
}


BOOL PVideoOutputDevicePPM::Open(const PString & name,
                                 BOOL /*startImmediate*/)
{
  Close();

  PFilePath path = name;
  if (!PDirectory::Exists(path.GetDirectory()))
    return FALSE;

  if (path != psprintf(path, 12345))
    deviceName = path;
  else
    deviceName = path.GetDirectory() + path.GetTitle() + "%u" + path.GetType();

  return TRUE;
}


BOOL PVideoOutputDevicePPM::IsOpen()
{
  return !deviceName;
}


BOOL PVideoOutputDevicePPM::Close()
{
  deviceName.MakeEmpty();
  return TRUE;
}


PStringList PVideoOutputDevicePPM::GetDeviceNames() const
{
  PStringList list;
  list += PDirectory();
  return list;
}


BOOL PVideoOutputDevicePPM::EndFrame()
{
  PFile file;
  if (!file.Open(psprintf(deviceName, frameNumber++), PFile::WriteOnly)) {
    PTRACE(1, "PPMVid\tFailed to open PPM output file \""
           << file.GetName() << "\": " << file.GetErrorText());
    return FALSE;
  }

  file << "P6 " << frameWidth  << " " << frameHeight << " " << 255 << "\n";

  if (!file.Write(frameStore, frameStore.GetSize())) {
    PTRACE(1, "PPMVid\tFailed to write frame data to PPM output file " << file.GetName());
    return FALSE;
  }

  PTRACE(6, "PPMVid\tFinished writing PPM file " << file.GetName());
  return file.Close();
}

#endif // SHOULD_BE_MOVED_TO_PLUGIN


///////////////////////////////////////////////////////////////////////////////
// PVideoInputDevice

BOOL PVideoInputDevice::CanCaptureVideo() const
{
  return TRUE;
}

static const char videoInputPluginBaseClass[] = "PVideoInputDevice";


PStringList PVideoInputDevice::GetDriverNames(PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsProviding(videoInputPluginBaseClass);
}


PStringList PVideoInputDevice::GetDriversDeviceNames(const PString & driverName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsDeviceNames(driverName, videoInputPluginBaseClass);
}


PVideoInputDevice * PVideoInputDevice::CreateDevice(const PString &driverName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PVideoInputDevice *)pluginMgr->CreatePluginsDevice(driverName, videoInputPluginBaseClass);
}


PVideoInputDevice * PVideoInputDevice::CreateDeviceByName(const PString & deviceName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PVideoInputDevice *)pluginMgr->CreatePluginsDeviceByName(deviceName, videoInputPluginBaseClass);
}


PVideoInputDevice * PVideoInputDevice::CreateOpenedDevice(const PString & driverName,
                                                          const PString & deviceName,
                                                          BOOL startImmediate,
                                                          PPluginManager * pluginMgr)
{
  PVideoInputDevice * device;
  if (driverName.IsEmpty() || driverName == "*")
    device = CreateDeviceByName(deviceName, pluginMgr);
  else
    device = CreateDevice(driverName, pluginMgr);

  if (device != NULL && device->Open(deviceName, startImmediate))
    return device;

  delete device;
  return NULL;
}


BOOL PVideoInputDevice::GetFrame(PBYTEArray & frame)
{
  PINDEX returned;
  if (!GetFrameData(frame.GetPointer(GetMaxFrameBytes()), &returned))
    return FALSE;

  frame.SetSize(returned);
  return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////////////

static const char videoOutputPluginBaseClass[] = "PVideoOutputDevice";


PStringList PVideoOutputDevice::GetDriverNames(PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsProviding(videoOutputPluginBaseClass);
}


PStringList PVideoOutputDevice::GetDriversDeviceNames(const PString & driverName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsDeviceNames(driverName, videoOutputPluginBaseClass);
}


PVideoOutputDevice * PVideoOutputDevice::CreateDevice(const PString & driverName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PVideoOutputDevice *)pluginMgr->CreatePluginsDevice(driverName, videoOutputPluginBaseClass);
}


PVideoOutputDevice * PVideoOutputDevice::CreateDeviceByName(const PString & deviceName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PVideoOutputDevice *)pluginMgr->CreatePluginsDeviceByName(deviceName, videoOutputPluginBaseClass);
}


PVideoOutputDevice * PVideoOutputDevice::CreateOpenedDevice(const PString &driverName,
                                                            const PString &deviceName,
                                                            BOOL startImmediate,
                                                            PPluginManager * pluginMgr)
{
  PVideoOutputDevice * device;
  if (driverName.IsEmpty() || driverName == "*")
    device = CreateDeviceByName(deviceName, pluginMgr);
  else
    device = CreateDevice(driverName, pluginMgr);

  if (device != NULL && device->Open(deviceName, startImmediate))
    return device;

  delete device;
  return NULL;
}


// End Of File ///////////////////////////////////////////////////////////////
