/*
 * sound.cxx
 *
 * Code for pluigns sound device
 *
 * Portable Windows Library
 *
 * Copyright (c) 2003 Post Increment
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
 * The Initial Developer of the Original Code is Post Increment
 *
 * Contributor(s): Craig Southeren
 *                 Snark at GnomeMeeting
 *
 * $Log: sound.cxx,v $
 * Revision 1.11  2005/08/09 09:08:11  rjongbloed
 * Merged new video code from branch back to the trunk.
 *
 * Revision 1.10.8.1  2005/07/17 09:27:08  rjongbloed
 * Major revisions of the PWLib video subsystem including:
 *   removal of F suffix on colour formats for vertical flipping, all done with existing bool
 *   working through use of RGB and BGR formats so now consistent
 *   cleaning up the plug in system to use virtuals instead of pointers to functions.
 *   rewrite of SDL to be a plug in compatible video output device.
 *   extensive enhancement of video test program
 *
 * Revision 1.10  2004/11/17 10:13:14  csoutheren
 * Fixed compilation with gcc 4.0.0
 *
 * Revision 1.9  2004/10/28 20:07:10  csoutheren
 * Fixes for MacOSX platforms, thanks to Hannes Friederich
 *
 * Revision 1.8  2004/08/16 06:40:59  csoutheren
 * Added adapters template to make device plugins available via the abstract factory interface
 *
 * Revision 1.7  2004/04/03 23:53:10  csoutheren
 * Added various changes to improce compatibility with the Sun Forte compiler
 *   Thanks to Brian Cameron
 * Added detection of readdir_r version
 *
 * Revision 1.6  2004/04/02 04:07:54  ykiryanov
 * Added ifndef BeOS for PSound
 *
 * Revision 1.5  2003/11/12 08:55:58  csoutheren
 * Added newline at end of file to remove gcc warning
 *
 * Revision 1.4  2003/11/12 05:17:25  csoutheren
 * Added more backwards compatibility functions for PSoundChannel
 *
 * Revision 1.3  2003/11/12 04:42:02  csoutheren
 * Removed non-specific code when compiling for WIn32
 *
 * Revision 1.2  2003/11/12 03:27:25  csoutheren
 * Initial version of plugin code from Snark of GnomeMeeting with changes
 *    by Craig Southeren of Post Increment
 *
 * Revision 1.1.2.1  2003/10/07 01:33:19  csoutheren
 * Initial checkin of pwlib code to do plugins.
 * Modified from original code and concept provided by Snark of Gnomemeeting
 *
 */

#ifdef __GNUC__
#pragma implementation "sound.h"
#endif

#include <ptlib.h>

#include <ptlib/sound.h>
#include <ptlib/pluginmgr.h>

static const char soundPluginBaseClass[] = "PSoundChannel";

template <> PSoundChannel * PDevicePluginFactory<PSoundChannel>::Worker::Create(const PString & type) const
{
  return PSoundChannel::CreateChannel(type);
}

namespace PWLib {
  PFactory<PDevicePluginAdapterBase>::Worker< PDevicePluginAdapter<PSoundChannel> > soundChannelFactoryAdapter("PSoundChannel", TRUE);
};

namespace PWLibStupidWindowsHacks {
  int loadSoundStuff;
};


PStringList PSoundChannel::GetDriverNames(PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsProviding(soundPluginBaseClass);
}


PStringList PSoundChannel::GetDriversDeviceNames(const PString & driverName,
                                                 PSoundChannel::Directions dir,
                                                 PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsDeviceNames(driverName, soundPluginBaseClass, dir);
}


PSoundChannel * PSoundChannel::CreateChannel(const PString & driverName, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PSoundChannel *)pluginMgr->CreatePluginsDevice(driverName, soundPluginBaseClass, 0);
}


PSoundChannel * PSoundChannel::CreateChannelByName(const PString & deviceName,
                                                   PSoundChannel::Directions dir,
                                                   PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return (PSoundChannel *)pluginMgr->CreatePluginsDeviceByName(deviceName, soundPluginBaseClass, dir);
}


PSoundChannel * PSoundChannel::CreateOpenedChannel(const PString & driverName,
                                                   const PString & deviceName,
                                                   PSoundChannel::Directions dir,
                                                   unsigned numChannels,
                                                   unsigned sampleRate,
                                                   unsigned bitsPerSample,
                                                   PPluginManager * pluginMgr)
{
  PSoundChannel * sndChan;
  if (driverName.IsEmpty() || driverName == "*")
    sndChan = CreateChannelByName(deviceName, dir, pluginMgr);
  else
    sndChan = CreateChannel(driverName, pluginMgr);

  if (sndChan != NULL && sndChan->Open(deviceName, dir, numChannels, sampleRate, bitsPerSample))
    return sndChan;

  delete sndChan;
  return NULL;
}


PStringList PSoundChannel::GetDeviceNames(PSoundChannel::Directions dir, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsDeviceNames("*", soundPluginBaseClass, dir);
}


PString PSoundChannel::GetDefaultDevice(Directions dir)
{
  PStringList devices = GetDeviceNames(dir);
  if (devices.GetSize() > 0)
    return devices[0];

  return PString::Empty();
}


PSoundChannel::PSoundChannel()
{
  baseChannel = NULL;
}

PSoundChannel::~PSoundChannel()
{
  delete baseChannel;
}

PSoundChannel::PSoundChannel(const PString & device,
                             Directions dir,
                             unsigned numChannels,
                             unsigned sampleRate,
                             unsigned bitsPerSample)
{
  baseChannel = NULL;
  Open(device, dir, numChannels, sampleRate, bitsPerSample);
}

BOOL PSoundChannel::Open(const PString & device,
                         Directions dir,
                         unsigned numChannels,
                         unsigned sampleRate,
                         unsigned bitsPerSample)
{
  if (baseChannel == NULL) {
    PStringArray names = GetDriverNames();
    if (names.GetSize() == 0)
      return FALSE;

    baseChannel = CreateChannel(names[0]);
  }

  if (baseChannel == NULL)
    return FALSE;

  return baseChannel->Open(device, dir, numChannels, sampleRate, bitsPerSample);
}

///////////////////////////////////////////////////////////////////////////

#if !defined(_WIN32) && !defined(__BEOS__) && !defined(__APPLE__)

PSound::PSound(unsigned channels,
               unsigned samplesPerSecond,
               unsigned bitsPerSample,
               PINDEX   bufferSize,
               const BYTE * buffer)
{
  encoding = 0;
  numChannels = channels;
  sampleRate = samplesPerSecond;
  sampleSize = bitsPerSample;
  SetSize(bufferSize);
  if (buffer != NULL)
    memcpy(GetPointer(), buffer, bufferSize);
}


PSound::PSound(const PFilePath & filename)
{
  encoding = 0;
  numChannels = 1;
  sampleRate = 8000;
  sampleSize = 16;
  Load(filename);
}


PSound & PSound::operator=(const PBYTEArray & data)
{
  PBYTEArray::operator=(data);
  return *this;
}


void PSound::SetFormat(unsigned channels,
                       unsigned samplesPerSecond,
                       unsigned bitsPerSample)
{
  encoding = 0;
  numChannels = channels;
  sampleRate = samplesPerSecond;
  sampleSize = bitsPerSample;
  formatInfo.SetSize(0);
}


BOOL PSound::Load(const PFilePath & /*filename*/)
{
  return FALSE;
}


BOOL PSound::Save(const PFilePath & /*filename*/)
{
  return FALSE;
}


BOOL PSound::Play()
{
  return Play(PSoundChannel::GetDefaultDevice(PSoundChannel::Player));
}


BOOL PSound::Play(const PString & device)
{

  PSoundChannel channel(device, PSoundChannel::Player);
  if (!channel.IsOpen())
    return FALSE;

  return channel.PlaySound(*this, TRUE);
}


BOOL PSound::PlayFile(const PFilePath & file, BOOL wait)
{
  PSoundChannel channel(PSoundChannel::GetDefaultDevice(PSoundChannel::Player),
                        PSoundChannel::Player);
  if (!channel.IsOpen())
    return FALSE;

  return channel.PlayFile(file, wait);
}


#endif //_WIN32
