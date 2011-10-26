/*
 * pluginmgr.cxx
 *
 * Plugin Manager Class
 *
 * Portable Windows Library
 *
 * Contributor(s): Snark at GnomeMeeting
 *
 * $Log: pluginmgr.cxx,v $
 * Revision 1.29  2005/11/30 12:47:42  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.28  2005/08/09 09:08:11  rjongbloed
 * Merged new video code from branch back to the trunk.
 *
 * Revision 1.27.4.1  2005/07/17 09:27:08  rjongbloed
 * Major revisions of the PWLib video subsystem including:
 *   removal of F suffix on colour formats for vertical flipping, all done with existing bool
 *   working through use of RGB and BGR formats so now consistent
 *   cleaning up the plug in system to use virtuals instead of pointers to functions.
 *   rewrite of SDL to be a plug in compatible video output device.
 *   extensive enhancement of video test program
 *
 * Revision 1.27  2005/01/11 06:57:15  csoutheren
 * Fixed namespace collisions with plugin starup factories
 *
 * Revision 1.26  2004/08/16 06:40:59  csoutheren
 * Added adapters template to make device plugins available via the abstract factory interface
 *
 * Revision 1.25  2004/07/12 09:17:21  csoutheren
 * Fixed warnings and errors under Linux
 *
 * Revision 1.24  2004/07/06 10:12:54  csoutheren
 * Added static integer o factory template to assist in ensuring factories are instantiated
 *
 * Revision 1.23  2004/06/30 12:17:06  rjongbloed
 * Rewrite of plug in system to use single global variable for all factories to avoid all sorts
 *   of issues with startup orders and Windows DLL multiple instances.
 *
 * Revision 1.22  2004/06/24 23:10:28  csoutheren
 * Require plugins to have _pwplugin suffix
 *
 * Revision 1.21  2004/06/03 13:30:59  csoutheren
 * Renamed INSTANTIATE_FACTORY to avoid potential namespace collisions
 * Added documentaton on new PINSTANTIATE_FACTORY macro
 * Added generic form of PINSTANTIATE_FACTORY
 *
 * Revision 1.20  2004/06/03 12:47:59  csoutheren
 * Decomposed PFactory declarations to hopefully avoid problems with Windows DLLs
 *
 * Revision 1.19  2004/06/01 05:44:57  csoutheren
 * Added OnShutdown to allow cleanup on exit
 *
 * Revision 1.18  2004/05/18 06:01:13  csoutheren
 * Deferred plugin loading until after main has executed by using abstract factory classes
 *
 * Revision 1.17  2004/05/06 11:29:35  rjongbloed
 * Added "current directory" to default plug in path.
 *
 * Revision 1.16  2004/05/02 17:06:42  ykiryanov
 * Ifdefd inclusion of algorithm for BeOS
 *
 * Revision 1.15  2004/05/02 08:37:56  rjongbloed
 * Fixed loading of plug ins when multiple plug in class sets used. Especially H.323 codecs.
 *
 * Revision 1.14  2004/04/22 11:43:48  csoutheren
 * Factored out functions useful for loading dynamic libraries
 *
 * Revision 1.13  2004/04/14 08:12:04  csoutheren
 * Added support for generic plugin managers
 *
 * Revision 1.12  2004/04/09 06:03:47  csoutheren
 * Cannot do PProcess virtual, so code is now in the plugin manager
 *
 * Revision 1.11  2004/04/09 05:54:41  csoutheren
 * Added ability for application to specify plugin directorories, or to specify directories by environment variable
 *
 * Revision 1.10  2004/03/23 04:43:42  csoutheren
 * Modified plugin manager to allow code modules to be notified when plugins
 * are loaded or unloaded
 *
 * Revision 1.9  2004/02/23 23:56:01  csoutheren
 * Removed unneeded class
 *
 * Revision 1.8  2004/01/18 21:00:15  dsandras
 * Fixed previous commit thanks to Craig Southeren!
 *
 * Revision 1.7  2004/01/17 17:40:57  csoutheren
 * Changed to only attempt loading of files with the correct library file extension
 * Changed to handle plugins without a register function
 *
 * Revision 1.6  2004/01/17 16:02:59  dereksmithies
 * make test for plugin names case insensitive.
 *
 * Revision 1.5  2003/11/18 10:39:56  csoutheren
 * Changed PTRACE levels to give better output at trace level 3
 *
 * Revision 1.4  2003/11/12 10:27:11  csoutheren
 * Changes to allow operation of static plugins under Windows
 *
 * Revision 1.3  2003/11/12 06:58:59  csoutheren
 * Added default plugin directory for Windows
 *
 * Revision 1.2  2003/11/12 03:27:25  csoutheren
 * Initial version of plugin code from Snark of GnomeMeeting with changes
 *    by Craig Southeren of Post Increment
 *
 *
 */

#include <ptlib.h>
#include <ptlib/pluginmgr.h>

#ifndef __BEOS__
#include <algorithm>
#endif

#ifndef P_DEFAULT_PLUGIN_DIR
#  ifdef  _WIN32
#    define P_DEFAULT_PLUGIN_DIR ".;C:\\PWLIB_PLUGINS"
#  else
#    define P_DEFAULT_PLUGIN_DIR ".:/usr/lib/pwlib"
#  endif
#endif

#ifdef  _WIN32
#define DIR_SEP   ";"
#else
#define DIR_SEP   ":"
#endif

#define ENV_PWLIB_PLUGIN_DIR  "PWLIBPLUGINDIR"

#define PWPLUGIN_SUFFIX       "_pwplugin"


const char PDevicePluginServiceDescriptor::SeparatorChar = '\t';


//////////////////////////////////////////////////////

void PPluginManager::LoadPluginDirectory (const PDirectory & dir)
{ 
  PLoadPluginDirectory<PPluginManager>(*this, dir, PWPLUGIN_SUFFIX); 
}

PStringArray PPluginManager::GetPluginDirs()
{
  PString env = ::getenv(ENV_PWLIB_PLUGIN_DIR);
  if (env == NULL)
    env = P_DEFAULT_PLUGIN_DIR;

  // split into directories on correct seperator
  return env.Tokenise(DIR_SEP, TRUE);
}

PPluginManager & PPluginManager::GetPluginManager()
{
  static PPluginManager systemPluginMgr;
  return systemPluginMgr;
}

BOOL PPluginManager::LoadPlugin(const PString & fileName)
{
  PWaitAndSignal m(pluginListMutex);

  PDynaLink *dll = new PDynaLink(fileName);
  if (!dll->IsLoaded()) {
    PTRACE(4, "Failed to open " << fileName);
  }

  else {
    unsigned (*GetAPIVersion)();
    if (!dll->GetFunction("PWLibPlugin_GetAPIVersion", (PDynaLink::Function &)GetAPIVersion)) {
      PTRACE(3, fileName << " is not a PWLib plugin");
    }

    else {
      int version = (*GetAPIVersion)();
      switch (version) {
        case 0 : // old-style service plugins, and old-style codec plugins
          {
            // declare local pointer to register function
            void (*triggerRegister)(PPluginManager *);

            // call the register function (if present)
            if (dll->GetFunction("PWLibPlugin_TriggerRegister", (PDynaLink::Function &)triggerRegister)) 
              (*triggerRegister)(this);
            else {
              PTRACE(3, fileName << " has no registration-trigger function");
            }
          }
          // fall through to new version

        case 1 : // factory style plugins
          // call the notifier
          CallNotifier(*dll, 0);

          // add the plugin to the list of plugins
          pluginList.Append(dll);
          return TRUE;

        default:
          PTRACE(3, fileName << " uses version " << version << " of the PWLIB PLUGIN API, which is not supported");
          break;
      }
    }
  }

  // loading the plugin failed - return error
  dll->Close();
  delete dll;

  return FALSE;
}

PStringList PPluginManager::GetPluginTypes() const
{
  PWaitAndSignal n(serviceListMutex);

  PStringList result;
  for (PINDEX i = 0; i < serviceList.GetSize(); i++) {
    PString serviceType = serviceList[i].serviceType;
    if (result.GetStringsIndex(serviceType) == P_MAX_INDEX)
      result.AppendString(serviceList[i].serviceType);
  }
  return result;
}

PStringList PPluginManager::GetPluginsProviding(const PString & serviceType) const
{
  PWaitAndSignal n(serviceListMutex);

  PStringList result;
  for (PINDEX i = 0; i < serviceList.GetSize(); i++) {
    if (serviceList[i].serviceType *= serviceType)
      result.AppendString(serviceList[i].serviceName);
  }
  return result;
}

PPluginServiceDescriptor * PPluginManager::GetServiceDescriptor (const PString & serviceName,
                                   const PString & serviceType) const
{
  PWaitAndSignal n(serviceListMutex);

  for (PINDEX i = 0; i < serviceList.GetSize(); i++) {
    if ((serviceList[i].serviceName *= serviceName) &&
        (serviceList[i].serviceType *= serviceType))
      return serviceList[i].descriptor;
  }
  return NULL;
}


PObject * PPluginManager::CreatePluginsDevice(const PString & serviceName,
                                              const PString & serviceType,
                                              int userData) const
{
  PDevicePluginServiceDescriptor * descr = (PDevicePluginServiceDescriptor *)GetServiceDescriptor(serviceName, serviceType);
  if (descr != NULL)
    return descr->CreateInstance(userData);

  return NULL;
}


PObject * PPluginManager::CreatePluginsDeviceByName(const PString & deviceName,
                                                    const PString & serviceType,
                                                    int userData) const
{
  // If have tab character, then have explicit driver name in device
  PINDEX tab = deviceName.Find(PDevicePluginServiceDescriptor::SeparatorChar);
  if (tab != P_MAX_INDEX)
    return CreatePluginsDevice(deviceName.Left(tab), serviceType, userData);

  // Otherwise search for the correct driver
  PWaitAndSignal m(serviceListMutex);

  for (PINDEX i = 0; i < serviceList.GetSize(); i++) {
    const PPluginService & service = serviceList[i];
    if (service.serviceType *= serviceType) {
      PDevicePluginServiceDescriptor * descriptor = (PDevicePluginServiceDescriptor *)service.descriptor;
      if (descriptor->ValidateDeviceName(deviceName, userData))
        return descriptor->CreateInstance(userData);
    }
  }

  return NULL;
}


bool PDevicePluginServiceDescriptor::ValidateDeviceName(const PString & deviceName, int userData) const
{
  PStringList devices = GetDeviceNames(userData);
  for (PINDEX j = 0; j < devices.GetSize(); j++) {
    if (devices[j] *= deviceName)
      return true;
  }

  return false;
}


PStringList PPluginManager::GetPluginsDeviceNames(const PString & serviceName,
                                                  const PString & serviceType,
                                                  int userData) const
{
  PStringList allDevices;

  if (serviceName.IsEmpty() || serviceName == "*") {
    PWaitAndSignal n(serviceListMutex);

    PINDEX i;
    PStringToString deviceToPluginMap;  

    // First we run through all of the drivers and their lists of devices and
    // use the dictionary to assure all names are unique
    for (i = 0; i < serviceList.GetSize(); i++) {
      const PPluginService & service = serviceList[i];
      if (service.serviceType *= serviceType) {
        PStringList devices = ((PDevicePluginServiceDescriptor *)service.descriptor)->GetDeviceNames(userData);
        for (PINDEX j = 0; j < devices.GetSize(); j++) {
          PCaselessString device = devices[j];
          if (deviceToPluginMap.Contains(device)) {
            PString oldPlugin = deviceToPluginMap[device];
            if (!oldPlugin.IsEmpty()) {
              // Make name unique by prepending driver name and a tab character
              deviceToPluginMap.SetAt(oldPlugin+PDevicePluginServiceDescriptor::SeparatorChar+device, "");
              // Reset the original to empty string so we dont add it multiple times
              deviceToPluginMap.SetAt(device, "");
            }
            // Now add the new one
            deviceToPluginMap.SetAt(service.serviceName+PDevicePluginServiceDescriptor::SeparatorChar+device, "");
          }
          else
            deviceToPluginMap.SetAt(device, service.serviceName);
        }
      }
    }

    for (i = 0; i < deviceToPluginMap.GetSize(); i++)
      allDevices.AppendString(deviceToPluginMap.GetKeyAt(i));
  }
  else {
    PDevicePluginServiceDescriptor * descr =
                            (PDevicePluginServiceDescriptor *)GetServiceDescriptor(serviceName, serviceType);
    if (descr != NULL)
      allDevices = descr->GetDeviceNames(userData);
  }

  return allDevices;
}


BOOL PPluginManager::RegisterService(const PString & serviceName,
             const PString & serviceType,
             PPluginServiceDescriptor * descriptor)
{
  PWaitAndSignal m(serviceListMutex);

  // first, check if it something didn't already register that name and type
  for (PINDEX i = 0; i < serviceList.GetSize(); i++) {
    if (serviceList[i].serviceName == serviceName &&
        serviceList[i].serviceType == serviceType)
      return FALSE;
  }  

  PPluginService * service = new PPluginService(serviceName, serviceType, descriptor);
  serviceList.Append(service);

  PDevicePluginAdapterBase * adapter = PFactory<PDevicePluginAdapterBase>::CreateInstance(serviceType);
  if (adapter != NULL)
    adapter->CreateFactory(serviceName);

  return TRUE;
}


void PPluginManager::AddNotifier(const PNotifier & notifyFunction, BOOL existing)
{
  PWaitAndSignal m(notifierMutex);
  notifierList.Append(new PNotifier(notifyFunction));

  if (existing)
    for (PINDEX i = 0; i < pluginList.GetSize(); i++) 
      CallNotifier(pluginList[i], 0);
}

void PPluginManager::RemoveNotifier(const PNotifier & notifyFunction)
{
  PWaitAndSignal m(notifierMutex);
  for (PINDEX i = 0; i < notifierList.GetSize(); i++) {
    if (notifierList[i] == notifyFunction) {
      notifierList.RemoveAt(i);
      i = 0;
      continue;
    }
  }
}

void PPluginManager::CallNotifier(PDynaLink & dll, INT code)
{
  PWaitAndSignal m(notifierMutex);
  for (PINDEX i = 0; i < notifierList.GetSize(); i++)
    notifierList[i](dll, code);
}

////////////////////////////////////////////////////////////////////////////////////

PPluginModuleManager::PPluginModuleManager(const char * _signatureFunctionName, PPluginManager * _pluginMgr)
  : signatureFunctionName(_signatureFunctionName)
{
  pluginList.DisallowDeleteObjects();
  pluginMgr = _pluginMgr;;
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();
}

void PPluginModuleManager::OnLoadModule(PDynaLink & dll, INT code)
{
  PDynaLink::Function dummyFunction;
  if (!dll.GetFunction(signatureFunctionName, dummyFunction))
    return;

  switch (code) {
    case 0:
      pluginList.SetAt(dll.GetName(), &dll); 
      break;

    case 1: 
      {
        PINDEX idx = pluginList.GetValuesIndex(dll.GetName());
        if (idx != P_MAX_INDEX)
          pluginList.RemoveAt(idx);
      }
      break;

    default:
      break;
  }

  OnLoadPlugin(dll, code);
}


////////////////////////////////////////////////////////////////////////////////////

class PluginLoaderStartup : public PProcessStartup
{
  PCLASSINFO(PluginLoaderStartup, PProcessStartup);
  public:
    void OnStartup()
    { 
      // load the actual DLLs, which will also load the system plugins
      PStringArray dirs = PPluginManager::GetPluginDirs();
      PPluginManager & mgr = PPluginManager::GetPluginManager();
      PINDEX i;
      for (i = 0; i < dirs.GetSize(); i++) 
        mgr.LoadPluginDirectory(dirs[i]);

      // now load the plugin module managers
      PFactory<PPluginModuleManager>::KeyList_T keyList = PFactory<PPluginModuleManager>::GetKeyList();
      PFactory<PPluginModuleManager>::KeyList_T::const_iterator r;
      for (r = keyList.begin(); r != keyList.end(); ++r) {
        PPluginModuleManager * mgr = PFactory<PPluginModuleManager>::CreateInstance(*r);
        if (mgr == NULL) {
          PTRACE(1, "PLUGIN\tCannot create manager for plugins of type " << *r);
        } else {
          PTRACE(1, "PLUGIN\tCreated manager for plugins of type " << *r);
          managers.push_back(mgr);
        }
      }
    }

    void OnShutdown()
    {
      while (managers.begin() != managers.end()) {
        std::vector<PPluginModuleManager *>::iterator r = managers.begin();
        PPluginModuleManager * mgr = *r;
        managers.erase(r);
        mgr->OnShutdown();
      }
    }

  protected:
    std::vector<PPluginModuleManager *> managers;
};

static PFactory<PProcessStartup>::Worker<PluginLoaderStartup> pluginLoaderStartupFactory("PluginLoader", true);

PINSTANTIATE_FACTORY(PluginLoaderStartup, PString)


