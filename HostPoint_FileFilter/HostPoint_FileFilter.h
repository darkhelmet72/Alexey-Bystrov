#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>


#define DRIVE_ARRAY_SIZE 32
#define WIN_7 (NTDDI_VERSION >= NTDDI_VISTA)
#define HOSTPOINT_REG_KEY_NAME  (L"\\Registry\\Machine\\SOFTWARE\\ControlSystem")
#define FREE_BUF_SIZE 50

#pragma warning(disable:4200)

#if defined (_X86_)
//#pragma comment(lib,"x86\ntstrsafe.lib")
#pragma comment(lib,"/x86/fltMgr.lib")
#else
#pragma comment(lib,"/x64/fltMgr.lib")
#endif

//---------------------------------------------------------------------------------------------------------
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
//---------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------
typedef struct _HOSTPOINT_FILEDLP
{
	DWORD TotalLockUSB;
	DWORD LockProcExecuteLocal; // Лочим все операции запуска на локальных дисках
	DWORD LockProcExecuteUSB; //Лочим все операции запуска на USB

	PUNICODE_STRING HostPointExtensionsUSB;
	ULONG HostPointExtensionCountUSB;
	PUNICODE_STRING HostPointProcessesUSB;
	ULONG HostPointProcessesCountUSB;
	PUNICODE_STRING HostPointUsersUSB;
	ULONG HostPointUsersCountUSB;	
	PUNICODE_STRING HostPointProcessesLEUSB;
	ULONG HostPointProcessesLECountUSB;
	PUNICODE_STRING HostPointUsersLEUSB;
	ULONG HostPointUsersLECountUSB;

	PUNICODE_STRING HostPointProcessesLELocal;
	ULONG HostPointProcessesLECountLocal;
	PUNICODE_STRING HostPointUsersLELocal;
	ULONG HostPointUsersLECountLocal;
	PUNICODE_STRING HostPointExtensionsLocal;
	ULONG HostPointExtensionCountLocal;
	PUNICODE_STRING HostPointProcessesLocal;
	ULONG HostPointProcessesCountLocal;
	PUNICODE_STRING HostPointUsersLocal;
	ULONG HostPointUsersCountLocal;
} HOSTPOINT_FILEDLP, *PHOSTPOINT_FILEDLP;
//---------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------
FLT_POSTOP_CALLBACK_STATUS HostPoint_FilePostCreate(IN OUT PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects,
	                                                IN PVOID CompletionContext,	IN FLT_POST_OPERATION_FLAGS Flags);
//---------------------------------------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS HostPoint_FilePreCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects,
	                                              __deref_out_opt PVOID *CompletionContext);
//---------------------------------------------------------------------------------------------------------
NTSTATUS HostPoint_FilterUnload(IN FLT_FILTER_UNLOAD_FLAGS Flags);
//---------------------------------------------------------------------------------------------------------
NTSTATUS HostPoint_FilterLoad(IN PCFLT_RELATED_OBJECTS  FltObjects, IN FLT_INSTANCE_SETUP_FLAGS  Flags,
	                      IN DEVICE_TYPE  VolumeDeviceType,IN FLT_FILESYSTEM_TYPE  VolumeFilesystemType);
//---------------------------------------------------------------------------------------------------------
NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath);
//---------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_OnUnload(IN PDRIVER_OBJECT DriverObject);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetMultiStrParams(IN PCWSTR value, IN OUT PUNICODE_STRING *str, IN OUT ULONG *strcount);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetStrParams(IN PCWSTR value, IN OUT PUNICODE_STRING *str);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetDwordParams(IN PCWSTR value, IN OUT DWORD *strcount);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_AllocateStr(_Inout_ PUNICODE_STRING str);
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_FreeStr(_Inout_ PUNICODE_STRING str, IN ULONG strcount);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_CmpStr(_In_ PUNICODE_STRING str1, _In_ PUNICODE_STRING str2, _In_ ULONG strcount);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_IsDeniedProcess(IN PUNICODE_STRING processlist, IN ULONG listcount);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_IsDeniedUser(IN PUNICODE_STRING userlist, IN ULONG listcount);
//---------------------------------------------------------------------------------------------------------
ULONG HostPoint_DriveType(IN PFLT_VOLUME Volume);
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_CreateLogDir();
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_InitLog();
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_WriteLog(char *wstr, PUNICODE_STRING wstr_);
//---------------------------------------------------------------------------------------------------------
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry) 
#pragma alloc_text(INIT, HostPoint_GetMultiStrParams) 
#pragma alloc_text(INIT, HostPoint_GetDwordParams)
#pragma alloc_text(INIT, HostPoint_GetStrParams)
#pragma alloc_text(INIT, HostPoint_InitLog)
#pragma alloc_text(INIT, HostPoint_CreateLogDir)
#pragma alloc_text(PAGE, HostPoint_WriteLog)
#pragma alloc_text(PAGE, HostPoint_IsDeniedProcess)
#pragma alloc_text(PAGE, HostPoint_IsDeniedUser)
#pragma alloc_text(PAGE, HostPoint_CmpStr)
#pragma alloc_text(PAGE, HostPoint_AllocateStr)
#pragma alloc_text(PAGE, HostPoint_DriveType)
#pragma alloc_text(PAGE, HostPoint_FreeStr) 
#pragma alloc_text(PAGE, HostPoint_FilterLoad)
#pragma alloc_text(PAGE, HostPoint_FilePreCreate)
#endif
//----------------------------------------------------------------------------------	
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
//----------------------------------------------------------------------------------	
//----------------------------------------------------------------------------------	
const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_CREATE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	HostPoint_FilePreCreate, HostPoint_FilePostCreate
	},
	{ IRP_MJ_OPERATION_END }
};
//---------------------------------------------------------------------------------------------------------
const FLT_CONTEXT_REGISTRATION Contexts[] = { { FLT_CONTEXT_END } };
//---------------------------------------------------------------------------------------------------------
const FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),                       //  Size
	FLT_REGISTRATION_VERSION,                       //  Version
	0,                                              //  Flags
	Contexts,                                           //  Context
	Callbacks,                                      //  Operation callbacks
	HostPoint_FilterUnload,                                   //  Filters unload routine
	HostPoint_FilterLoad,                            //  InstanceSetup routine
	NULL,                                           //  InstanceQueryTeardown routine
	NULL,                                           //  InstanceTeardownStart routine
	NULL,                                           //  InstanceTeardownComplete routine
	NULL,                                           //  Filename generation support callback
	NULL,                                           //  Filename normalization support callback
	NULL,                                           //  Normalize name component cleanup callback
#if WIN_7    
	NULL,                                           //  Transaction notification callback
	NULL                                            //  Filename normalization support callback   
#endif  
};
//----------------------------------------------------------------------------------	
//----------------------------------------------------------------------------------	
QUERY_INFO_PROCESS ZwQueryInformationProcess;
PFLT_FILTER pFilter;
HOSTPOINT_FILEDLP FileDLP;
HANDLE LogFile;