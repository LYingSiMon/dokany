/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2020 Google, Inc.
  Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
  Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

  http://dokan-dev.github.io

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "dokani.h"
#include "fileinfo.h"
#include "list.h"
#include <conio.h>
#include <process.h>
#include <stdlib.h>
#include <tchar.h>
#include <strsafe.h>
#include <assert.h>

#define DokanMapKernelBit(dest, src, userBit, kernelBit)                       \
  if (((src) & (kernelBit)) == (kernelBit))                                    \
  (dest) |= (userBit)

// DokanOptions->DebugMode is ON?
BOOL g_DebugMode = TRUE;

// DokanOptions->UseStdErr is ON?
BOOL g_UseStdErr = TRUE;

// Dokan DLL critical section
CRITICAL_SECTION g_InstanceCriticalSection;

// Global linked list of mounted Dokan instances
LIST_ENTRY g_InstanceList;

// Global thread pool
PTP_POOL g_ThreadPool = NULL;

VOID DOKANAPI DokanUseStdErr(BOOL Status) { g_UseStdErr = Status; }

VOID DOKANAPI DokanDebugMode(BOOL Status) { g_DebugMode = Status; }

int InitializeThreadPool() {
  EnterCriticalSection(&g_InstanceCriticalSection);
  {
    if (g_ThreadPool) {
      DokanDbgPrint("Dokan Error: Thread pool has already been created.\n");
      LeaveCriticalSection(&g_InstanceCriticalSection);
      return DOKAN_DRIVER_INSTALL_ERROR;
    }

    // It seems this is only needed if LoadLibrary() and FreeLibrary() are used and it should be called by the exe
    // SetThreadpoolCallbackLibrary(&g_ThreadPoolCallbackEnvironment, hModule);
    g_ThreadPool = CreateThreadpool(NULL);
    if (!g_ThreadPool) {
      DokanDbgPrint("Dokan Error: Failed to create thread pool.\n");
      LeaveCriticalSection(&g_InstanceCriticalSection);
      return DOKAN_DRIVER_INSTALL_ERROR;
    }
  }
  LeaveCriticalSection(&g_InstanceCriticalSection);
  return DOKAN_SUCCESS;
}

void CleanupThreadpool() {
  EnterCriticalSection(&g_InstanceCriticalSection);
  {
    if (g_ThreadPool) {
      CloseThreadpool(g_ThreadPool);
      g_ThreadPool = NULL;
    }
  }
  LeaveCriticalSection(&g_InstanceCriticalSection);
}

void PushIoEventBuffer(PDOKAN_IO_EVENT IoEvent) {
  LONG currentSize = InterlockedDecrement(&IoEvent->EventContextBatchSize);
  if (currentSize <= 0) {
    free(IoEvent);
  }
}

VOID DispatchDriverLogs(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext) {
  UNREFERENCED_PARAMETER(IoEvent);

  PDOKAN_LOG_MESSAGE log_message =
      (PDOKAN_LOG_MESSAGE)((PCHAR)EventContext + sizeof(EVENT_CONTEXT));
  if (log_message->MessageLength) {
    ULONG paquet_size = FIELD_OFFSET(DOKAN_LOG_MESSAGE, Message[0]) +
                        log_message->MessageLength;
    if (((PCHAR)log_message + paquet_size) <=
        ((PCHAR)EventContext + EventContext->Length)) {
      DbgPrint("DriverLog: %.*s\n", log_message->MessageLength,
               log_message->Message);
    } else {
      DbgPrint("Invalid driver log message received.\n");
    }
  }
  PushIoEventBuffer(IoEvent);
}

void ResetOverlapped(DOKAN_OVERLAPPED *overlapped) {
  if (overlapped) {
    RtlZeroMemory(overlapped, sizeof(DOKAN_OVERLAPPED));
  }
}

PDOKAN_INSTANCE
NewDokanInstance() {
  PDOKAN_INSTANCE instance = (PDOKAN_INSTANCE)malloc(sizeof(DOKAN_INSTANCE));
  if (instance == NULL)
    return NULL;

  ZeroMemory(instance, sizeof(DOKAN_INSTANCE));

  instance->GlobalDevice = INVALID_HANDLE_VALUE;
  instance->Device = INVALID_HANDLE_VALUE;
  instance->NotifyHandle = INVALID_HANDLE_VALUE;
  instance->KeepaliveHandle = INVALID_HANDLE_VALUE;

  (void)InitializeCriticalSectionAndSpinCount(&instance->CriticalSection,
                                              0x80000400);

  InitializeListHead(&instance->ListEntry);

  instance->DeviceClosedWaitHandle = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!instance->DeviceClosedWaitHandle) {
    DokanDbgPrint("Dokan Error: Cannot create Dokan instance because the "
                  "device closed wait handle could not be created.\n");
    DeleteCriticalSection(&instance->CriticalSection);
    free(instance);
    return NULL;
  }

  EnterCriticalSection(&g_InstanceCriticalSection);
  {
    if (!g_ThreadPool) {
      DokanDbgPrint("Dokan Error: Cannot create Dokan instance because the "
                    "thread pool hasn't been created.\n");
      LeaveCriticalSection(&g_InstanceCriticalSection);
      DeleteCriticalSection(&instance->CriticalSection);
      CloseHandle(instance->DeviceClosedWaitHandle);
      free(instance);
      return NULL;
    }

    instance->ThreadInfo.ThreadPool = g_ThreadPool;
    instance->ThreadInfo.CleanupGroup = CreateThreadpoolCleanupGroup();
    if (!instance->ThreadInfo.CleanupGroup) {
      DokanDbgPrint(
          "Dokan Error: Failed to create thread pool cleanup group.\n");
      LeaveCriticalSection(&g_InstanceCriticalSection);
      DeleteCriticalSection(&instance->CriticalSection);
      CloseHandle(instance->DeviceClosedWaitHandle);
      free(instance);
      return NULL;
    }
    InitializeThreadpoolEnvironment(&instance->ThreadInfo.CallbackEnvironment);
    SetThreadpoolCallbackPool(&instance->ThreadInfo.CallbackEnvironment,
                              g_ThreadPool);
    SetThreadpoolCallbackCleanupGroup(&instance->ThreadInfo.CallbackEnvironment,
                                      instance->ThreadInfo.CleanupGroup, NULL);
    InsertTailList(&g_InstanceList, &instance->ListEntry);
  }
  LeaveCriticalSection(&g_InstanceCriticalSection);
  return instance;
}

VOID DeleteDokanInstance(PDOKAN_INSTANCE Instance) {
  SetEvent(Instance->DeviceClosedWaitHandle);
  if (Instance->ThreadInfo.CleanupGroup) {
    CloseThreadpoolCleanupGroupMembers(Instance->ThreadInfo.CleanupGroup, FALSE,
                                       Instance);
    CloseThreadpoolCleanupGroup(Instance->ThreadInfo.CleanupGroup);
    Instance->ThreadInfo.CleanupGroup = NULL;
    DestroyThreadpoolEnvironment(&Instance->ThreadInfo.CallbackEnvironment);
    // Members freed by CloseThreadpoolCleanupGroupMembers():
    Instance->ThreadInfo.IoCompletion = NULL;
  }
  if (Instance->NotifyHandle &&
      Instance->NotifyHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(Instance->NotifyHandle);
  }
  if (Instance->KeepaliveHandle &&
      Instance->KeepaliveHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(Instance->KeepaliveHandle);
  }
  if (Instance->Device && Instance->Device != INVALID_HANDLE_VALUE) {
    CloseHandle(Instance->Device);
  }
  if (Instance->GlobalDevice &&
      Instance->GlobalDevice != INVALID_HANDLE_VALUE) {
    CloseHandle(Instance->GlobalDevice);
  }
  DeleteCriticalSection(&Instance->CriticalSection);
  EnterCriticalSection(&g_InstanceCriticalSection);
  { RemoveEntryList(&Instance->ListEntry); }
  LeaveCriticalSection(&g_InstanceCriticalSection);
  CloseHandle(Instance->DeviceClosedWaitHandle);
  free(Instance);
}

BOOL IsMountPointDriveLetter(LPCWSTR mountPoint) {
  size_t mountPointLength;

  if (!mountPoint || *mountPoint == 0) {
    return FALSE;
  }

  mountPointLength = wcslen(mountPoint);

  if (mountPointLength == 1 ||
      (mountPointLength == 2 && mountPoint[1] == L':') ||
      (mountPointLength == 3 && mountPoint[1] == L':' &&
       mountPoint[2] == L'\\')) {

    return TRUE;
  }

  return FALSE;
}

BOOL IsValidDriveLetter(WCHAR DriveLetter) {
  return (L'a' <= DriveLetter && DriveLetter <= L'z') ||
         (L'A' <= DriveLetter && DriveLetter <= L'Z');
}

BOOL CheckDriveLetterAvailability(WCHAR DriveLetter) {
  DWORD result = 0;
  WCHAR buffer[MAX_PATH];
  WCHAR dosDevice[] = L"\\\\.\\C:";
  WCHAR driveName[] = L"C:";
  WCHAR driveLetter = towupper(DriveLetter);
  HANDLE device = NULL;
  dosDevice[4] = driveLetter;
  driveName[0] = driveLetter;

  DokanMountPointsCleanUp();

  if (!IsValidDriveLetter(driveLetter)) {
    DbgPrintW(L"CheckDriveLetterAvailability failed, bad drive letter %c\n",
              DriveLetter);
    return FALSE;
  }

  device = CreateFile(dosDevice, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                      FILE_FLAG_NO_BUFFERING, NULL);

  if (device != INVALID_HANDLE_VALUE) {
    DbgPrintW(L"CheckDriveLetterAvailability failed, %c: is already used\n",
              DriveLetter);
    CloseHandle(device);
    return FALSE;
  }

  ZeroMemory(buffer, MAX_PATH * sizeof(WCHAR));
  result = QueryDosDevice(driveName, buffer, MAX_PATH);
  if (result > 0) {
    DbgPrintW(L"CheckDriveLetterAvailability failed, QueryDosDevice - Drive "
              L"letter \"%c\" is already used.\n",
              DriveLetter);
    return FALSE;
  }

  DWORD drives = GetLogicalDrives();
  result = (drives >> (driveLetter - L'A') & 0x00000001);
  if (result > 0) {
    DbgPrintW(L"CheckDriveLetterAvailability failed, GetLogicalDrives - Drive "
              L"letter \"%c\" is already used.\n",
              DriveLetter);
    return FALSE;
  }

  return TRUE;
}

void CheckAllocationUnitSectorSize(PDOKAN_OPTIONS DokanOptions) {
  ULONG allocationUnitSize = DokanOptions->AllocationUnitSize;
  ULONG sectorSize = DokanOptions->SectorSize;

  if ((allocationUnitSize < 512 || allocationUnitSize > 65536 ||
       (allocationUnitSize & (allocationUnitSize - 1)) != 0) // Is power of two
      || (sectorSize < 512 || sectorSize > 65536 ||
          (sectorSize & (sectorSize - 1)))) { // Is power of two
    // Reset to default if values does not fit windows FAT/NTFS value
    // https://support.microsoft.com/en-us/kb/140365
    DokanOptions->SectorSize = DOKAN_DEFAULT_SECTOR_SIZE;
    DokanOptions->AllocationUnitSize = DOKAN_DEFAULT_ALLOCATION_UNIT_SIZE;
  }

  DbgPrintW(L"AllocationUnitSize: %d SectorSize: %d\n",
            DokanOptions->AllocationUnitSize, DokanOptions->SectorSize);
}

BOOL StartDeviceIO(PDOKAN_INSTANCE DokanInstance, DOKAN_OVERLAPPED *Overlapped) {
  DWORD lastError = 0;
  DWORD eventBatchSize = EVENT_CONTEXT_MAX_SIZE * 4;
  PDOKAN_IO_EVENT ioEvent = malloc((SIZE_T)FIELD_OFFSET(DOKAN_IO_EVENT, EventContext) + eventBatchSize);
  if (!ioEvent) {
    DokanDbgPrint("Dokan Error: Failed to allocate IO event buffer.\n");
    return FALSE;
  }

  ioEvent->DokanInstance = DokanInstance;
  if (!Overlapped) {
    Overlapped = malloc(sizeof(DOKAN_OVERLAPPED));
    if (!Overlapped) {
      DokanDbgPrint("Dokan Error: Failed to allocate overlapped info.\n");
      free(ioEvent);
      return FALSE;
    }
    ResetOverlapped(Overlapped);
  }

  Overlapped->OutputPayload = ioEvent;
  Overlapped->PayloadType = DOKAN_OVERLAPPED_TYPE_IOEVENT;
  StartThreadpoolIo(DokanInstance->ThreadInfo.IoCompletion);
  if (!DeviceIoControl(DokanInstance->Device, // Handle to device
                       FSCTL_EVENT_WAIT,      // IO Control code
                       NULL,                  // Input Buffer to driver.
                       0, // Length of input buffer in bytes.
                       &ioEvent->EventContext[0], // Output Buffer from driver.
                       eventBatchSize, // Length of output buffer in bytes.
                       NULL,           // Bytes placed in buffer.
                       (OVERLAPPED *)Overlapped // asynchronous call
                       )) {
    lastError = GetLastError();
    if (lastError != ERROR_IO_PENDING) {
      DbgPrint(
          "Dokan Error: Dokan device ioctl failed for wait with code %d.\n",
          lastError);
      CancelThreadpoolIo(DokanInstance->ThreadInfo.IoCompletion);
      free(ioEvent);
      free(Overlapped);
      return FALSE;
    }
  }
  DokanDbgPrint("StartDeviceIO SUCCESSS\n");
  return TRUE;
}

BOOL DOKANAPI DokanIsFileSystemRunning(_In_ DOKAN_HANDLE DokanInstance) {
  DOKAN_INSTANCE *instance = (DOKAN_INSTANCE *)DokanInstance;
  if (!instance) {
    return FALSE;
  }
  return WaitForSingleObject(instance->DeviceClosedWaitHandle, 0) ==
                 WAIT_TIMEOUT
             ? TRUE
             : FALSE;
}

DWORD DOKANAPI DokanWaitForFileSystemClosed(DOKAN_HANDLE DokanInstance,
                                            DWORD dwMilliseconds) {
  DOKAN_INSTANCE *instance = (DOKAN_INSTANCE *)DokanInstance;
  if (!instance) {
    return FALSE;
  }
  return WaitForSingleObject(instance->DeviceClosedWaitHandle, dwMilliseconds);
}

void DOKANAPI DokanCloseHandle(DOKAN_HANDLE DokanInstance) {
  DOKAN_INSTANCE *instance = (DOKAN_INSTANCE *)DokanInstance;
  if (!instance) {
    return;
  }
  // make sure the driver is unmounted
  DokanRemoveMountPoint(instance->MountPoint);
  DokanWaitForFileSystemClosed((DOKAN_HANDLE)instance, INFINITE);
  DeleteDokanInstance(instance);
}

int DOKANAPI DokanMain(PDOKAN_OPTIONS DokanOptions,
                       PDOKAN_OPERATIONS DokanOperations) {
  DOKAN_INSTANCE *instance = NULL;
  int returnCode;
  returnCode = DokanCreateFileSystem(DokanOptions, DokanOperations,
                                     (DOKAN_HANDLE *)&instance);
  if (returnCode != DOKAN_SUCCESS) {
    return returnCode;
  }
  DokanWaitForFileSystemClosed((DOKAN_HANDLE)instance, INFINITE);
  DeleteDokanInstance(instance);
  return returnCode;
}

int DOKANAPI DokanCreateFileSystem(_In_ PDOKAN_OPTIONS DokanOptions,
                                   _In_ PDOKAN_OPERATIONS DokanOperations,
                                   _Out_ DOKAN_HANDLE *DokanInstance) {
  PDOKAN_INSTANCE instance;
  WCHAR rawDeviceName[MAX_PATH];

  g_DebugMode = DokanOptions->Options & DOKAN_OPTION_DEBUG;
  g_UseStdErr = DokanOptions->Options & DOKAN_OPTION_STDERR;

  if (g_DebugMode) {
    DbgPrintW(L"Dokan: debug mode on\n");
  }

  if (g_UseStdErr) {
    DbgPrintW(L"Dokan: use stderr\n");
    g_DebugMode = TRUE;
  }

  if ((DokanOptions->Options & DOKAN_OPTION_NETWORK) &&
      !IsMountPointDriveLetter(DokanOptions->MountPoint)) {
    DokanOptions->Options &= ~DOKAN_OPTION_NETWORK;
    DbgPrintW(L"Dokan: Mount point folder is specified with network device "
              L"option. Disable network device.\n");
  }

  if (DokanOptions->Version < DOKAN_MINIMUM_COMPATIBLE_VERSION) {
    DokanDbgPrintW(
        L"Dokan Error: Incompatible version (%d), minimum is (%d) \n",
        DokanOptions->Version, DOKAN_MINIMUM_COMPATIBLE_VERSION);
    return DOKAN_VERSION_ERROR;
  }

  CheckAllocationUnitSectorSize(DokanOptions);
  instance = NewDokanInstance();
  if (!instance) {
    return DOKAN_DRIVER_INSTALL_ERROR;
  }

  instance->DokanOptions = DokanOptions;
  instance->DokanOperations = DokanOperations;
  instance->GlobalDevice =
      CreateFile(DOKAN_GLOBAL_DEVICE_NAME,           // lpFileName
                 0,                                  // dwDesiredAccess
                 FILE_SHARE_READ | FILE_SHARE_WRITE, // dwShareMode
                 NULL,                               // lpSecurityAttributes
                 OPEN_EXISTING,                      // dwCreationDistribution
                 0,                                  // dwFlagsAndAttributes
                 NULL                                // hTemplateFile
      );
  if (instance->GlobalDevice == INVALID_HANDLE_VALUE) {
    DWORD lastError = GetLastError();
    DokanDbgPrintW(L"Dokan Error: CreatFile failed to open %s: %d\n",
                   DOKAN_GLOBAL_DEVICE_NAME, lastError);
    DeleteDokanInstance(instance);
    return DOKAN_DRIVER_INSTALL_ERROR;
  }

  DbgPrint("Global device opened\n");
  if (DokanOptions->MountPoint != NULL) {
    wcscpy_s(instance->MountPoint, sizeof(instance->MountPoint) / sizeof(WCHAR),
             DokanOptions->MountPoint);
    if (IsMountPointDriveLetter(instance->MountPoint) &&
        !CheckDriveLetterAvailability(instance->MountPoint[0])) {
      DokanDbgPrint("Dokan Error: CheckDriveLetterAvailability Failed\n");
      DeleteDokanInstance(instance);
      return DOKAN_MOUNT_ERROR;
    }
  }

  if (DokanOptions->UNCName != NULL) {
    wcscpy_s(instance->UNCName, sizeof(instance->UNCName) / sizeof(WCHAR),
             DokanOptions->UNCName);
  }

  if (!DokanStart(instance)) {
    DeleteDokanInstance(instance);
    return DOKAN_START_ERROR;
  }

  GetRawDeviceName(instance->DeviceName, rawDeviceName, MAX_PATH);
  instance->Device =
      CreateFile(rawDeviceName,                      // lpFileName
                 0,                                  // dwDesiredAccess
                 FILE_SHARE_READ | FILE_SHARE_WRITE, // dwShareMode
                 NULL,                               // lpSecurityAttributes
                 OPEN_EXISTING,                      // dwCreationDistribution
                 FILE_FLAG_OVERLAPPED,               // dwFlagsAndAttributes
                 NULL                                // hTemplateFile
      );
  if (instance->Device == INVALID_HANDLE_VALUE) {
    DWORD lastError = GetLastError();
    DokanDbgPrintW(L"Dokan Error: CreatFile failed to open %s: %d\n",
                   rawDeviceName, lastError);
    DeleteDokanInstance(instance);
    return DOKAN_DRIVER_INSTALL_ERROR;
  }

  instance->ThreadInfo.IoCompletion =
      CreateThreadpoolIo(instance->Device, DokanLoop, instance,
                         &instance->ThreadInfo.CallbackEnvironment);
  if (!instance->ThreadInfo.IoCompletion) {
    DokanDbgPrintW(L"Dokan Error: Failed to allocate IO completion port.\n");
    DeleteDokanInstance(instance);
    return DOKAN_DRIVER_INSTALL_ERROR;
  }

  if (!StartDeviceIO(instance, NULL)) {
    DokanDbgPrint("Dokan Error: Failed to  start device IO.\n");
    DeleteDokanInstance(instance);
    return DOKAN_START_ERROR;
  } else {
    DbgPrint("Dokan Information: Started device IO.\n");
  }

  if (!DokanMount(instance->MountPoint, instance->DeviceName, DokanOptions)) {
    SendReleaseIRP(instance->DeviceName);
    DokanDbgPrint("Dokan Error: DokanMount Failed\n");
    DeleteDokanInstance(instance);
    return DOKAN_MOUNT_ERROR;
  }

  wchar_t keepalive_path[128];
  StringCbPrintfW(keepalive_path, sizeof(keepalive_path), L"\\\\?%s%s",
                  instance->DeviceName, DOKAN_KEEPALIVE_FILE_NAME);
  HANDLE keepalive_handle =
      CreateFile(keepalive_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (keepalive_handle == INVALID_HANDLE_VALUE) {
    // We don't consider this a fatal error because the keepalive handle is only
    // needed for abnormal termination cases anyway.
    DbgPrintW(L"Failed to open keepalive file: %s\n", keepalive_path);
  } else {
    DWORD keepalive_bytes_returned = 0;
    if (!DeviceIoControl(keepalive_handle, FSCTL_ACTIVATE_KEEPALIVE, NULL, 0,
                         NULL, 0, &keepalive_bytes_returned, NULL))
      DbgPrintW(L"Failed to activate keepalive handle.\n");
  }

  if (DokanOptions->Options & DOKAN_OPTION_ENABLE_NOTIFICATION_API) {
    wchar_t notify_path[128];
    StringCbPrintfW(notify_path, sizeof(notify_path), L"\\\\?%s%s",
                    instance->DeviceName, DOKAN_NOTIFICATION_FILE_NAME);
    instance->NotifyHandle = CreateFile(
        notify_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (instance->NotifyHandle == INVALID_HANDLE_VALUE) {
      DbgPrintW(L"Failed to open notify handle: %s\n", notify_path);
    }
  }

  // Here we should have been mounter by mountmanager thanks to
  // IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME
  DbgPrintW(L"Dokan Information: mounted: %s -> %s\n", instance->MountPoint,
            instance->DeviceName);

  /* if (DokanOperations->Mounted) {
    DOKAN_MOUNTED_INFO mountedInfo;
    mountedInfo.DokanOptions = DokanOptions;
    mountedInfo.ThreadPool = instance->ThreadInfo.ThreadPool;
    DokanOperations->Mounted(&mountedInfo);
  }*/

  if (DokanInstance) {
    *DokanInstance = instance;
  }

  /*CloseHandle(device);

  if (DokanOperations->Unmounted) {
    DOKAN_FILE_INFO fileInfo;
    RtlZeroMemory(&fileInfo, sizeof(DOKAN_FILE_INFO));
    fileInfo.DokanOptions = DokanOptions;
    // ignore return value
    DokanOperations->Unmounted(&fileInfo);
  }

  DbgPrint("\nunload\n");*/
  return DOKAN_SUCCESS;
}

VOID
GetRawDeviceName(LPCWSTR DeviceName, LPWSTR DestinationBuffer,
                 rsize_t DestinationBufferSizeInElements) {
  if (DeviceName && DestinationBuffer && DestinationBufferSizeInElements > 0) {
    wcscpy_s(DestinationBuffer, DestinationBufferSizeInElements, L"\\\\.");
    wcscat_s(DestinationBuffer, DestinationBufferSizeInElements, DeviceName);
  }
}

void ALIGN_ALLOCATION_SIZE(PLARGE_INTEGER size, PDOKAN_OPTIONS DokanOptions) {
  long long r = size->QuadPart % DokanOptions->AllocationUnitSize;
  size->QuadPart =
      (size->QuadPart + (r > 0 ? DokanOptions->AllocationUnitSize - r : 0));
}



VOID CALLBACK DispatchCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter,
                             PTP_WORK Work) {
  UNREFERENCED_PARAMETER(Instance);
  UNREFERENCED_PARAMETER(Work);

  PDOKAN_CALLBACK_PARAM callbackParam = (PDOKAN_CALLBACK_PARAM)Parameter;
  DOKAN_IO_EVENT *currentIoEvent = callbackParam->IoEvent;
  PEVENT_CONTEXT context = callbackParam->EventContext;
  DokanDbgPrintW(L"DISPTACH START \n");
  switch (context->MajorFunction) {
  case IRP_MJ_CREATE:
    DispatchCreate(currentIoEvent, context);
    break;
  case IRP_MJ_CLEANUP:
    DispatchCleanup(currentIoEvent, context);
    break;
  case IRP_MJ_CLOSE:
    DispatchClose(currentIoEvent, context);
    break;
  case IRP_MJ_DIRECTORY_CONTROL:
    DispatchDirectoryInformation(currentIoEvent, context);
    break;
  case IRP_MJ_READ:
    DispatchRead(currentIoEvent, context);
    break;
  case IRP_MJ_WRITE:
    DispatchWrite(currentIoEvent, context);
    break;
  case IRP_MJ_QUERY_INFORMATION:
    DispatchQueryInformation(currentIoEvent, context);
    break;
  case IRP_MJ_QUERY_VOLUME_INFORMATION:
    DispatchQueryVolumeInformation(currentIoEvent, context);
    break;
  case IRP_MJ_LOCK_CONTROL:
    DispatchLock(currentIoEvent, context);
    break;
  case IRP_MJ_SET_INFORMATION:
    DispatchSetInformation(currentIoEvent, context);
    break;
  case IRP_MJ_FLUSH_BUFFERS:
    DispatchFlush(currentIoEvent, context);
    break;
  case IRP_MJ_QUERY_SECURITY:
    DispatchQuerySecurity(currentIoEvent, context);
    break;
  case IRP_MJ_SET_SECURITY:
    DispatchSetSecurity(currentIoEvent, context);
    break;
  case DOKAN_IRP_LOG_MESSAGE:
    DispatchDriverLogs(currentIoEvent, context);
    break;
  default:
    DokanDbgPrintW(L"Dokan Warning: Unsupported IRP 0x%x, event Info = 0x%p.\n",
                   context->MajorFunction, context);
    PushIoEventBuffer(currentIoEvent);
    break;
  }
  DokanDbgPrintW(L"DISPTACH DONE\n");
  free(callbackParam);
}


void OnDeviceIoCtlFailed(PDOKAN_INSTANCE Dokan, ULONG IoResult) {
	DokanDbgPrintW(L"Dokan Fatal: Closing IO processing for dokan instance %s with error code 0x%x and unmounting volume.\n", Dokan->DeviceName, IoResult);
	//DokanNotifyUnmounted(Dokan);

	// set the device to a closed state
	SetEvent(Dokan->DeviceClosedWaitHandle);
}

// Don't know what went wrong
// Life will never be the same again
// End it all
void HandleProcessIoFatalError(PDOKAN_INSTANCE Dokan, DOKAN_IO_EVENT *IoEvent,
                               DOKAN_OVERLAPPED *Overlapped, ULONG IoResult) {
  free(IoEvent);
  free(Overlapped);
  OnDeviceIoCtlFailed(Dokan, IoResult);
}

void ProcessIOEvent(PDOKAN_INSTANCE DokanInstance, DOKAN_OVERLAPPED *Overlapped,
                    ULONG IoResult, ULONG_PTR NumberOfBytesTransferred) {
  DOKAN_IO_EVENT *currentIoEvent = (DOKAN_IO_EVENT *)Overlapped->OutputPayload;
  currentIoEvent->KernelInfoSize = (ULONG)NumberOfBytesTransferred;
  currentIoEvent->EventContextBatchSize = 0;
  PEVENT_CONTEXT context = NULL;

  if (IoResult != NO_ERROR) {
    DbgPrintW(L"Dokan Warning: DeviceIoCtrl() has returned error code %u.\n",
              IoResult);
    HandleProcessIoFatalError(DokanInstance, currentIoEvent, Overlapped,
                              IoResult);
    return;
  }

  ResetOverlapped(Overlapped);

  BOOL restartDeviceIOSucceeded = FALSE;
  DWORD lastError = ERROR_SUCCESS;

  // Give PDOKAN_IO_EVENT with a pointer to their PEVENT_CONTEXT
  // Have ProcessKernelResultEvent that free the even when counter is 0

  if (NumberOfBytesTransferred > 0) {
    context = currentIoEvent->EventContext;
    while (NumberOfBytesTransferred) {
      NumberOfBytesTransferred -= context->Length;
      context = (PEVENT_CONTEXT)((char *)(context) + context->Length);
      ++currentIoEvent->EventContextBatchSize;
    }
    context = currentIoEvent->EventContext;
    LONG eventContextBatchSize = currentIoEvent->EventContextBatchSize;
    while (eventContextBatchSize) {
      PEVENT_CONTEXT nextContext =
          (PEVENT_CONTEXT)((char *)(context) + context->Length);
      // Note: It becomes unsafe to access the context after dispatching it.

      PDOKAN_CALLBACK_PARAM callbackParam =
          malloc(sizeof(DOKAN_CALLBACK_PARAM));
      if (!callbackParam) {
        DbgPrintW(L"Dokan Error: Callback param allocation failed.\n", );
        OnDeviceIoCtlFailed(DokanInstance, ERROR_OUTOFMEMORY);
        return;
      }

      callbackParam->IoEvent = currentIoEvent;
      callbackParam->EventContext = context;
      PTP_WORK work =
          CreateThreadpoolWork(DispatchCallback, callbackParam,
                               &DokanInstance->ThreadInfo.CallbackEnvironment);
      if (!work) {
        lastError = GetLastError();
        DbgPrintW(L"Dokan Error: CreateThreadpoolWork() has returned error "
                  L"code %u.\n",
                  lastError);
        OnDeviceIoCtlFailed(DokanInstance, lastError);
        return;
      }
      SubmitThreadpoolWork(work);

      --eventContextBatchSize;
      context = nextContext;
    }
  } else {
    free(currentIoEvent);
  }

  restartDeviceIOSucceeded = StartDeviceIO(DokanInstance, Overlapped);
  if (!restartDeviceIOSucceeded) {
    lastError = GetLastError();
    SetLastError(ERROR_SUCCESS);
  }

  if (!restartDeviceIOSucceeded) {
    // NOTE: This MUST be handled at the end of this method. OnDeviceIoCtlFailed() will unmount the volume
    // at which point the user-mode driver needs to wait on all outstanding IO operations in its Unmount()
    // callback before returning control to this handler. If OnDeviceIoCtlFailed() is called above there will
    // be 1 pending IO operation which could potentially queue an async operation. If everything gets cleaned up
    // before that operation completes then bad things could happen.
    OnDeviceIoCtlFailed(DokanInstance, lastError);
  }
}

// Process the result of SendEventInformation()
void ProcessKernelResultEvent(DOKAN_OVERLAPPED *Overlapped) {
  /* PDOKAN_IO_EVENT ioEvent = (PDOKAN_IO_EVENT)Overlapped->InputPayload;
  assert(ioEvent);*/
  free(Overlapped);
}

VOID CALLBACK DokanLoop(_Inout_ PTP_CALLBACK_INSTANCE Instance,
                        _Inout_opt_ PVOID Context, _Inout_opt_ PVOID Overlapped,
                        _In_ ULONG IoResult,
                        _In_ ULONG_PTR NumberOfBytesTransferred,
                        _Inout_ PTP_IO Io) {
  UNREFERENCED_PARAMETER(Instance);
  UNREFERENCED_PARAMETER(Io);

  PDOKAN_INSTANCE dokan = (PDOKAN_INSTANCE)Context;
  DOKAN_OVERLAPPED *overlapped = (DOKAN_OVERLAPPED *)Overlapped;
  assert(dokan);
  assert(overlapped);
  switch (overlapped->PayloadType) {
  case DOKAN_OVERLAPPED_TYPE_IOEVENT:
    ProcessIOEvent(dokan, overlapped, IoResult, NumberOfBytesTransferred);
    break;
  case DOKAN_OVERLAPPED_TYPE_IOEVENT_RESULT:
    ProcessKernelResultEvent(overlapped);
    break;
  default:
    DokanDbgPrintW(L"Unrecognized overlapped type of %d for dokan instance %s. "
                   L"The payload is probably being leaked.\n",
                   overlapped->PayloadType, dokan->DeviceName);
    free(overlapped);
    break;
  }
}

ULONG
GetEventInfoSize(__in ULONG MajorFunction, __in PEVENT_INFORMATION EventInfo) {
  if (MajorFunction == IRP_MJ_WRITE) {
    // For writes only, the reply is a fixed size and the BufferLength inside it
    // is the "bytes written" value as opposed to the reply size.
    return sizeof(EVENT_INFORMATION);
  }
  return max((ULONG)sizeof(EVENT_INFORMATION),
             FIELD_OFFSET(EVENT_INFORMATION, Buffer[0]) +
                 EventInfo->BufferLength);
}

BOOL SendEventInformation(PEVENT_INFORMATION EventInfo, PDOKAN_IO_EVENT IoEvent,
                          PEVENT_CONTEXT EventContext) {
  DOKAN_OVERLAPPED *overlapped = NULL;
  DWORD lastError = 0;
  ULONG eventInfoSize = GetEventInfoSize(EventContext->MajorFunction, EventInfo);
  DbgPrint("Dokan Information: SendEventInformation() with NTSTATUS 0x%x, "
           "context 0x%lx, and result object 0x%p with size %d\n",
           EventInfo->Status, EventInfo->Context, EventInfo, eventInfoSize);

  overlapped = malloc(sizeof(DOKAN_OVERLAPPED));
  if (!overlapped) {
    DbgPrint("Dokan Error: Failed to allocate overlapped info.\n");
    PushIoEventBuffer(IoEvent);
    return FALSE;
  }
  ResetOverlapped(overlapped);
  overlapped->InputPayload = IoEvent;
  overlapped->PayloadType = DOKAN_OVERLAPPED_TYPE_IOEVENT_RESULT;
  StartThreadpoolIo(IoEvent->DokanInstance->ThreadInfo.IoCompletion);
  if (!DeviceIoControl(IoEvent->DokanInstance->Device, // Handle to device
                       FSCTL_EVENT_INFO,               // IO Control code
                       EventInfo,     // Input Buffer to driver.
                       eventInfoSize, // Length of input buffer in bytes.
                       NULL,          // Output Buffer from driver.
                       0,             // Length of output buffer in bytes.
                       NULL,          // Bytes placed in buffer.
                       (OVERLAPPED *)overlapped // asynchronous call
                       )) {

    lastError = GetLastError();
    if (lastError != ERROR_IO_PENDING) {
      DbgPrint("Dokan Error: Dokan device result ioctl failed for wait with "
               "code %d.\n",
               lastError);
      CancelThreadpoolIo(IoEvent->DokanInstance->ThreadInfo.IoCompletion);
      free(overlapped);
      PushIoEventBuffer(IoEvent);
      return FALSE;
    }
  }
  PushIoEventBuffer(IoEvent);
  return TRUE;
}

VOID CheckFileName(LPWSTR FileName) {
  size_t len = wcslen(FileName);
  // if the beginning of file name is "\\",
  // replace it with "\"
  if (len >= 2 && FileName[0] == L'\\' && FileName[1] == L'\\') {
    int i;
    for (i = 0; FileName[i + 1] != L'\0'; ++i) {
      FileName[i] = FileName[i + 1];
    }
    FileName[i] = L'\0';
  }

  // Remove "\" in front of Directory
  len = wcslen(FileName);
  if (len > 2 && FileName[len - 1] == L'\\')
    FileName[len - 1] = '\0';
}

ULONG DispatchGetEventInformationLength(ULONG bufferSize) {
  // EVENT_INFORMATION has a buffer of size 8 already
  // we remote it to the struct size and add the requested buffer size
  // but we need at least to have enough space to set EVENT_INFORMATION
  return max((ULONG)sizeof(EVENT_INFORMATION),
             FIELD_OFFSET(EVENT_INFORMATION, Buffer[0]) + bufferSize);
}

PEVENT_INFORMATION
DispatchCommon(PEVENT_CONTEXT EventContext, ULONG SizeOfEventInfo,
               PDOKAN_INSTANCE DokanInstance, PDOKAN_FILE_INFO DokanFileInfo,
               PDOKAN_OPEN_INFO *DokanOpenInfo) {
  PEVENT_INFORMATION eventInfo = (PEVENT_INFORMATION)malloc(SizeOfEventInfo);

  if (eventInfo == NULL) {
    return NULL;
  }
  RtlZeroMemory(eventInfo, SizeOfEventInfo);
  RtlZeroMemory(DokanFileInfo, sizeof(DOKAN_FILE_INFO));

  eventInfo->BufferLength = 0;
  eventInfo->SerialNumber = EventContext->SerialNumber;

  DokanFileInfo->ProcessId = EventContext->ProcessId;
  DokanFileInfo->DokanOptions = DokanInstance->DokanOptions;
  if (EventContext->FileFlags & DOKAN_DELETE_ON_CLOSE) {
    DokanFileInfo->DeleteOnClose = 1;
  }
  if (EventContext->FileFlags & DOKAN_PAGING_IO) {
    DokanFileInfo->PagingIo = 1;
  }
  if (EventContext->FileFlags & DOKAN_WRITE_TO_END_OF_FILE) {
    DokanFileInfo->WriteToEndOfFile = 1;
  }
  if (EventContext->FileFlags & DOKAN_SYNCHRONOUS_IO) {
    DokanFileInfo->SynchronousIo = 1;
  }
  if (EventContext->FileFlags & DOKAN_NOCACHE) {
    DokanFileInfo->Nocache = 1;
  }

  *DokanOpenInfo = GetDokanOpenInfo(EventContext, DokanInstance);
  if (*DokanOpenInfo == NULL) {
    DbgPrint("error openInfo is NULL\n");
    return eventInfo;
  }

  DokanFileInfo->Context = (ULONG64)(*DokanOpenInfo)->UserContext;
  DokanFileInfo->IsDirectory = (UCHAR)(*DokanOpenInfo)->IsDirectory;
  DokanFileInfo->DokanContext = (ULONG64)(*DokanOpenInfo);

  eventInfo->Context = (ULONG64)(*DokanOpenInfo);

  return eventInfo;
}

PDOKAN_OPEN_INFO
GetDokanOpenInfo(PEVENT_CONTEXT EventContext, PDOKAN_INSTANCE DokanInstance) {
  PDOKAN_OPEN_INFO openInfo;
  EnterCriticalSection(&DokanInstance->CriticalSection);

  openInfo = (PDOKAN_OPEN_INFO)(UINT_PTR)EventContext->Context;
  if (openInfo != NULL) {
    openInfo->OpenCount++;
    openInfo->EventContext = EventContext;
    openInfo->DokanInstance = DokanInstance;
  }
  LeaveCriticalSection(&DokanInstance->CriticalSection);
  return openInfo;
}

VOID ReleaseDokanOpenInfo(PEVENT_INFORMATION EventInformation,
                          PDOKAN_FILE_INFO FileInfo,
                          PDOKAN_INSTANCE DokanInstance) {
  PDOKAN_OPEN_INFO openInfo;
  LPWSTR fileNameForClose = NULL;
  EnterCriticalSection(&DokanInstance->CriticalSection);

  openInfo = (PDOKAN_OPEN_INFO)(UINT_PTR)EventInformation->Context;
  if (openInfo != NULL) {
    openInfo->OpenCount--;
    if (openInfo->OpenCount < 1) {
      if (openInfo->DirListHead != NULL) {
        ClearFindData(openInfo->DirListHead);
        free(openInfo->DirListHead);
        openInfo->DirListHead = NULL;
      }
      if (openInfo->StreamListHead != NULL) {
        ClearFindStreamData(openInfo->StreamListHead);
        free(openInfo->StreamListHead);
        openInfo->StreamListHead = NULL;
      }
      if (openInfo->FileName) {
        fileNameForClose = openInfo->FileName;
      }
      free(openInfo);
      EventInformation->Context = 0;
    }
  }
  LeaveCriticalSection(&DokanInstance->CriticalSection);

  if (fileNameForClose) {
    if (DokanInstance->DokanOperations->CloseFile) {
      DokanInstance->DokanOperations->CloseFile(fileNameForClose, FileInfo);
    }
    free(fileNameForClose);
  }
}

// ask driver to release all pending IRP to prepare for Unmount.
BOOL SendReleaseIRP(LPCWSTR DeviceName) {
  ULONG returnedLength;
  WCHAR rawDeviceName[MAX_PATH];

  DbgPrintW(L"send release to %s\n", DeviceName);

  GetRawDeviceName(DeviceName, rawDeviceName, MAX_PATH);
  if (!SendToDevice(rawDeviceName,
                    FSCTL_EVENT_RELEASE, NULL, 0, NULL, 0, &returnedLength)) {

    DbgPrintW(L"Failed to unmount device:%s\n", DeviceName);
    return FALSE;
  }

  return TRUE;
}

BOOL SendGlobalReleaseIRP(LPCWSTR MountPoint) {
  if (MountPoint != NULL) {
    size_t length = wcslen(MountPoint);
    if (length > 0) {
      ULONG returnedLength;
      ULONG inputLength = sizeof(DOKAN_UNICODE_STRING_INTERMEDIATE) +
                          (MAX_PATH * sizeof(WCHAR));
      PDOKAN_UNICODE_STRING_INTERMEDIATE szMountPoint = malloc(inputLength);

      if (szMountPoint != NULL) {
        ZeroMemory(szMountPoint, inputLength);
        szMountPoint->MaximumLength = MAX_PATH * sizeof(WCHAR);
        szMountPoint->Length = (USHORT)(length * sizeof(WCHAR));
        CopyMemory(szMountPoint->Buffer, MountPoint, szMountPoint->Length);

        DbgPrintW(L"send global release for %s\n", MountPoint);

        if (!SendToDevice(DOKAN_GLOBAL_DEVICE_NAME, FSCTL_EVENT_RELEASE,
                          szMountPoint, inputLength, NULL, 0,
                          &returnedLength)) {

          DbgPrintW(L"Failed to unmount: %s\n", MountPoint);
          free(szMountPoint);
          return FALSE;
        }

        free(szMountPoint);
        return TRUE;
      }
    }
  }

  return FALSE;
}

BOOL DokanStart(PDOKAN_INSTANCE Instance) {
  EVENT_START eventStart;
  EVENT_DRIVER_INFO driverInfo;
  ULONG returnedLength = 0;

  ZeroMemory(&eventStart, sizeof(EVENT_START));
  ZeroMemory(&driverInfo, sizeof(EVENT_DRIVER_INFO));

  eventStart.UserVersion = DOKAN_DRIVER_VERSION;
  if (Instance->DokanOptions->Options & DOKAN_OPTION_ALT_STREAM) {
    eventStart.Flags |= DOKAN_EVENT_ALTERNATIVE_STREAM_ON;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_NETWORK) {
    eventStart.DeviceType = DOKAN_NETWORK_FILE_SYSTEM;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_REMOVABLE) {
    eventStart.Flags |= DOKAN_EVENT_REMOVABLE;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_WRITE_PROTECT) {
    eventStart.Flags |= DOKAN_EVENT_WRITE_PROTECT;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) {
    eventStart.Flags |= DOKAN_EVENT_MOUNT_MANAGER;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION) {
    eventStart.Flags |= DOKAN_EVENT_CURRENT_SESSION;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_FILELOCK_USER_MODE) {
    eventStart.Flags |= DOKAN_EVENT_FILELOCK_USER_MODE;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE) {
    eventStart.Flags |= DOKAN_EVENT_ENABLE_NETWORK_UNMOUNT;
  }
  if (Instance->DokanOptions->Options &
      DOKAN_OPTION_ENABLE_FCB_GARBAGE_COLLECTION) {
    eventStart.Flags |= DOKAN_EVENT_ENABLE_FCB_GC;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_CASE_SENSITIVE) {
    eventStart.Flags |= DOKAN_EVENT_CASE_SENSITIVE;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_DISPATCH_DRIVER_LOGS) {
    eventStart.Flags |= DOKAN_EVENT_DISPATCH_DRIVER_LOGS;
  }
  if (Instance->DokanOptions->Options & DOKAN_OPTION_ALLOW_IPC_BATCHING) {
    eventStart.Flags |= DOKAN_EVENT_ALLOW_IPC_BATCHING;
  }

  memcpy_s(eventStart.MountPoint, sizeof(eventStart.MountPoint),
           Instance->MountPoint, sizeof(Instance->MountPoint));
  memcpy_s(eventStart.UNCName, sizeof(eventStart.UNCName), Instance->UNCName,
           sizeof(Instance->UNCName));

  eventStart.IrpTimeout = Instance->DokanOptions->Timeout;

  SendToDevice(DOKAN_GLOBAL_DEVICE_NAME, FSCTL_EVENT_START, &eventStart,
               sizeof(EVENT_START), &driverInfo, sizeof(EVENT_DRIVER_INFO),
               &returnedLength);

  if (driverInfo.Status == DOKAN_START_FAILED) {
    if (driverInfo.DriverVersion != eventStart.UserVersion) {
      DokanDbgPrint("Dokan Error: driver version mismatch, driver %X, dll %X\n",
                    driverInfo.DriverVersion, eventStart.UserVersion);
    } else {
      DokanDbgPrint("Dokan Error: driver start error\n");
    }
    return FALSE;
  } else if (driverInfo.Status == DOKAN_MOUNTED) {
    Instance->MountId = driverInfo.MountId;
    Instance->DeviceNumber = driverInfo.DeviceNumber;
    wcscpy_s(Instance->DeviceName, sizeof(Instance->DeviceName) / sizeof(WCHAR),
             driverInfo.DeviceName);
    return TRUE;
  }
  return FALSE;
}

BOOL DOKANAPI DokanSetDebugMode(ULONG Mode) {
  ULONG returnedLength;
  return SendToDevice(DOKAN_GLOBAL_DEVICE_NAME, FSCTL_SET_DEBUG_MODE, &Mode,
                      sizeof(ULONG), NULL, 0, &returnedLength);
}

BOOL DOKANAPI DokanMountPointsCleanUp() {
    ULONG returnedLength;
    return SendToDevice(DOKAN_GLOBAL_DEVICE_NAME, FSCTL_MOUNTPOINT_CLEANUP, NULL,
        0, NULL, 0, &returnedLength);
}

BOOL SendToDevice(LPCWSTR DeviceName, DWORD IoControlCode, PVOID InputBuffer,
                  ULONG InputLength, PVOID OutputBuffer, ULONG OutputLength,
                  PULONG ReturnedLength) {
  HANDLE device;
  BOOL status;

  device = CreateFile(DeviceName,                         // lpFileName
                      0,                                  // dwDesiredAccess
                      FILE_SHARE_READ | FILE_SHARE_WRITE, // dwShareMode
                      NULL,          // lpSecurityAttributes
                      OPEN_EXISTING, // dwCreationDistribution
                      0,             // dwFlagsAndAttributes
                      NULL           // hTemplateFile
  );

  if (device == INVALID_HANDLE_VALUE) {
    DWORD dwErrorCode = GetLastError();
    DbgPrintW(L"Dokan Error: Failed to open %ws with code %d\n", DeviceName,
             dwErrorCode);
    return FALSE;
  }

  status = DeviceIoControl(device,         // Handle to device
                           IoControlCode,  // IO Control code
                           InputBuffer,    // Input Buffer to driver.
                           InputLength,    // Length of input buffer in bytes.
                           OutputBuffer,   // Output Buffer from driver.
                           OutputLength,   // Length of output buffer in bytes.
                           ReturnedLength, // Bytes placed in buffer.
                           NULL            // synchronous call
                           );

  CloseHandle(device);

  if (!status) {
    DbgPrint("DokanError: Ioctl 0x%x failed with code %d on Device %ws\n",
             IoControlCode, GetLastError(), DeviceName);
    return FALSE;
  }

  return TRUE;
}

PDOKAN_CONTROL DOKANAPI DokanGetMountPointList(BOOL uncOnly, PULONG nbRead) {
  ULONG returnedLength = 0;
  PDOKAN_CONTROL dokanControl = NULL;
  PDOKAN_CONTROL results = NULL;
  ULONG bufferLength = 32 * sizeof(*dokanControl);
  BOOL success;

  *nbRead = 0;

  do {
    if (dokanControl != NULL)
      free(dokanControl);
    dokanControl = malloc(bufferLength);
    if (dokanControl == NULL)
      return NULL;
    ZeroMemory(dokanControl, bufferLength);

    success =
        SendToDevice(DOKAN_GLOBAL_DEVICE_NAME, FSCTL_EVENT_MOUNTPOINT_LIST,
                     NULL, 0, dokanControl, bufferLength, &returnedLength);

    if (!success && GetLastError() != ERROR_MORE_DATA) {
      free(dokanControl);
      return NULL;
    }
    bufferLength *= 2;
  } while (!success);

  if (returnedLength == 0) {
    free(dokanControl);
    return NULL;
  }

  *nbRead = returnedLength / sizeof(DOKAN_CONTROL);
  results = malloc(returnedLength);
  if (results != NULL) {
    ZeroMemory(results, returnedLength);
    for (ULONG i = 0; i < *nbRead; ++i) {
      if (!uncOnly || wcscmp(dokanControl[i].UNCName, L"") != 0)
        CopyMemory(&results[i], &dokanControl[i], sizeof(DOKAN_CONTROL));
    }
  }
  free(dokanControl);
  return results;
}

VOID DOKANAPI DokanReleaseMountPointList(PDOKAN_CONTROL list) { free(list); }

BOOL WINAPI DllMain(HINSTANCE Instance, DWORD Reason, LPVOID Reserved) {
  UNREFERENCED_PARAMETER(Reserved);
  UNREFERENCED_PARAMETER(Instance);

  switch (Reason) {
  case DLL_PROCESS_ATTACH: {
    (void)InitializeCriticalSectionAndSpinCount(&g_InstanceCriticalSection,
                                          0x80000400);

    InitializeListHead(&g_InstanceList);
    InitializeThreadPool();
  } break;
  case DLL_PROCESS_DETACH: {
    EnterCriticalSection(&g_InstanceCriticalSection);

    while (!IsListEmpty(&g_InstanceList)) {
      PLIST_ENTRY entry = RemoveHeadList(&g_InstanceList);
      PDOKAN_INSTANCE instance =
          CONTAINING_RECORD(entry, DOKAN_INSTANCE, ListEntry);
      DokanRemoveMountPointEx(instance->MountPoint, FALSE);
      free(instance);
    }

    LeaveCriticalSection(&g_InstanceCriticalSection);
    DeleteCriticalSection(&g_InstanceCriticalSection);
    CleanupThreadpool();
  } break;
  default:
    break;
  }
  return TRUE;
}

void DOKANAPI DokanMapKernelToUserCreateFileFlags(
	ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG CreateOptions, ULONG CreateDisposition,
	ACCESS_MASK* outDesiredAccess, DWORD *outFileAttributesAndFlags, DWORD *outCreationDisposition) {
	BOOL genericRead = FALSE, genericWrite = FALSE, genericExecute = FALSE,
		genericAll = FALSE;

  if (outFileAttributesAndFlags) {

    *outFileAttributesAndFlags = FileAttributes;

    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_WRITE_THROUGH, FILE_WRITE_THROUGH);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_SEQUENTIAL_SCAN, FILE_SEQUENTIAL_ONLY);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_RANDOM_ACCESS, FILE_RANDOM_ACCESS);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_NO_BUFFERING, FILE_NO_INTERMEDIATE_BUFFERING);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_OPEN_REPARSE_POINT, FILE_OPEN_REPARSE_POINT);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_DELETE_ON_CLOSE, FILE_DELETE_ON_CLOSE);
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_BACKUP_SEMANTICS, FILE_OPEN_FOR_BACKUP_INTENT);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
    DokanMapKernelBit(*outFileAttributesAndFlags, CreateOptions,
                      FILE_FLAG_SESSION_AWARE, FILE_SESSION_AWARE);
#endif
  }

  if (outCreationDisposition) {

    switch (CreateDisposition) {
    case FILE_CREATE:
      *outCreationDisposition = CREATE_NEW;
      break;
    case FILE_OPEN:
      *outCreationDisposition = OPEN_EXISTING;
      break;
    case FILE_OPEN_IF:
      *outCreationDisposition = OPEN_ALWAYS;
      break;
    case FILE_OVERWRITE:
      *outCreationDisposition = TRUNCATE_EXISTING;
      break;
    case FILE_SUPERSEDE:
    // The documentation isn't clear on the difference between replacing a file
    // and truncating it.
    // For now we just map it to create/truncate
    case FILE_OVERWRITE_IF:
      *outCreationDisposition = CREATE_ALWAYS;
      break;
    default:
      *outCreationDisposition = 0;
      break;
    }
  }

  if (outDesiredAccess) {

	  *outDesiredAccess = DesiredAccess;

	  if ((*outDesiredAccess & FILE_GENERIC_READ) == FILE_GENERIC_READ) {
		  *outDesiredAccess |= GENERIC_READ;
		  genericRead = TRUE;
	  }
	  if ((*outDesiredAccess & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) {
		  *outDesiredAccess |= GENERIC_WRITE;
		  genericWrite = TRUE;
	  }
	  if ((*outDesiredAccess & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) {
		  *outDesiredAccess |= GENERIC_EXECUTE;
		  genericExecute = TRUE;
	  }
	  if ((*outDesiredAccess & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) {
		  *outDesiredAccess |= GENERIC_ALL;
		  genericAll = TRUE;
	  }

	  if (genericRead)
		  *outDesiredAccess &= ~FILE_GENERIC_READ;
	  if (genericWrite)
		  *outDesiredAccess &= ~FILE_GENERIC_WRITE;
	  if (genericExecute)
		  *outDesiredAccess &= ~FILE_GENERIC_EXECUTE;
	  if (genericAll)
		  *outDesiredAccess &= ~FILE_ALL_ACCESS;
  }
}

BOOL DOKANAPI DokanNotifyPath(LPCWSTR FilePath, ULONG CompletionFilter,
                              ULONG Action) {
  return FALSE;
  /* if (FilePath == NULL || g_notify_handle == INVALID_HANDLE_VALUE) {
    return FALSE;
  }
  size_t length = wcslen(FilePath);
  const size_t prefixSize = 2; // size of mount letter plus ":"
  if (length <= prefixSize) {
    return FALSE;
  }
  // remove the mount letter and colon from length, for example: "G:"
  length -= prefixSize;
  ULONG returnedLength;
  ULONG inputLength = (ULONG)(
      sizeof(DOKAN_NOTIFY_PATH_INTERMEDIATE) + (length * sizeof(WCHAR)));
  PDOKAN_NOTIFY_PATH_INTERMEDIATE pNotifyPath = malloc(inputLength);
  if (pNotifyPath == NULL) {
    DbgPrint("Failed to allocate NotifyPath\n");
    return FALSE;
  }
  ZeroMemory(pNotifyPath, inputLength);
  pNotifyPath->CompletionFilter = CompletionFilter;
  pNotifyPath->Action = Action;
  pNotifyPath->Length = (USHORT)(length * sizeof(WCHAR));
  CopyMemory(pNotifyPath->Buffer, FilePath + prefixSize, pNotifyPath->Length);
  if (!DeviceIoControl(g_notify_handle, FSCTL_NOTIFY_PATH, pNotifyPath,
                       inputLength, NULL, 0, &returnedLength, NULL)) {
    DbgPrint("Failed to send notify path command:%ws\n", FilePath);
    free(pNotifyPath);
    return FALSE;
  }
  free(pNotifyPath);
  return TRUE;*/
}

BOOL DOKANAPI DokanNotifyCreate(LPCWSTR FilePath, BOOL IsDirectory) {
  return DokanNotifyPath(FilePath,
                         IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME
                                     : FILE_NOTIFY_CHANGE_FILE_NAME,
                         FILE_ACTION_ADDED);
}

BOOL DOKANAPI DokanNotifyDelete(LPCWSTR FilePath, BOOL IsDirectory) {
  return DokanNotifyPath(FilePath,
                         IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME
                                     : FILE_NOTIFY_CHANGE_FILE_NAME,
                         FILE_ACTION_REMOVED);
}

BOOL DOKANAPI DokanNotifyUpdate(LPCWSTR FilePath) {
  return DokanNotifyPath(FilePath, FILE_NOTIFY_CHANGE_ATTRIBUTES,
                         FILE_ACTION_MODIFIED);
}

BOOL DOKANAPI DokanNotifyXAttrUpdate(LPCWSTR FilePath) {
  return DokanNotifyPath(FilePath, FILE_NOTIFY_CHANGE_ATTRIBUTES,
                         FILE_ACTION_MODIFIED);
}

BOOL DOKANAPI DokanNotifyRename(LPCWSTR OldPath, LPCWSTR NewPath,
                                BOOL IsDirectory, BOOL IsInSameDirectory) {
  BOOL success = DokanNotifyPath(
      OldPath,
      IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME,
      IsInSameDirectory ? FILE_ACTION_RENAMED_OLD_NAME : FILE_ACTION_REMOVED);
  success &= DokanNotifyPath(
      NewPath,
      IsDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME,
      IsInSameDirectory ? FILE_ACTION_RENAMED_NEW_NAME : FILE_ACTION_ADDED);
  return success;
}
