#include "HostPoint_FileFilter.h" 
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_WriteLog(char *wstr, PUNICODE_STRING wstr_)
{
	PAGED_CODE();

	CHAR  *buffer = NULL;
	size_t  cb;
	ULONG buffer_size = 0;
	BOOLEAN fl = FALSE;
	LARGE_INTEGER m_SysTime;
	LARGE_INTEGER CurrentLocalTime;
	TIME_FIELDS local_time = { 0 };
	IO_STATUS_BLOCK ioStatusBlock = { 0 };

	if (wstr == NULL || LogFile == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) return;

	if (wstr_ != NULL)
		buffer_size = (((ULONG)strlen(wstr) + wstr_->Length) + FREE_BUF_SIZE);
	else
		buffer_size = (ULONG)strlen(wstr) + FREE_BUF_SIZE;

	if (buffer_size <= FREE_BUF_SIZE) return;

	buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'hpst');
	if (buffer == NULL)
	{
		KdPrint(("[HostPoint]: Can`t Allocate memory in WriteLog routen.\n"));
		return;
	}
	else
	{
		KeQuerySystemTime(&m_SysTime);
		ExSystemTimeToLocalTime(&m_SysTime, &CurrentLocalTime);
		RtlTimeToTimeFields(&CurrentLocalTime, &local_time);

		RtlZeroMemory(buffer, buffer_size);
		if (wstr[0] != '-')
		{

			if (wstr_ == NULL)
			{
				if (NT_SUCCESS(RtlStringCbPrintfA(buffer, buffer_size, "[%d.%d.%d - %d:%d:%d] - %s\r\n",
					local_time.Day,
					local_time.Month,
					local_time.Year,
					local_time.Hour,
					local_time.Minute,
					local_time.Second, wstr)))
				if (NT_SUCCESS(RtlStringCbLengthA(buffer, buffer_size, &cb)))
					fl = TRUE;
			}
			else
			{
				if (NT_SUCCESS(RtlStringCbPrintfA(buffer, buffer_size, "[%d.%d.%d - %d:%d:%d] - %s %ws\r\n",
					local_time.Day,
					local_time.Month,
					local_time.Year,
					local_time.Hour,
					local_time.Minute,
					local_time.Second, wstr, wstr_->Buffer)))
				if (NT_SUCCESS(RtlStringCbLengthA(buffer, buffer_size, &cb)))
					fl = TRUE;
			}
		}
		else
		{
			if (NT_SUCCESS(RtlStringCbPrintfA(buffer, buffer_size, "%s\r\n",wstr)))
			if (NT_SUCCESS(RtlStringCbLengthA(buffer, buffer_size, &cb)))
				fl = TRUE;
		}
		if (fl)
		{
			ZwWriteFile(LogFile, NULL, NULL, NULL, &ioStatusBlock, buffer, cb, NULL, NULL);
		}
		ExFreePoolWithTag(buffer, 'hpst');
	}
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_CreateLogDir(WCHAR *LogDirName)
{
	UNICODE_STRING tmp1 = { 0 };
	OBJECT_ATTRIBUTES  objAttr = { 0 };
	HANDLE hDir = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };;
	BOOLEAN fl = FALSE;

	RtlInitUnicodeString(&tmp1, LogDirName);
	InitializeObjectAttributes(&objAttr, &tmp1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (NT_SUCCESS(ZwCreateFile(&hDir, GENERIC_WRITE,
		&objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0)))
	{
		fl = TRUE;
	}
	if (hDir != NULL) ZwClose(hDir);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_InitLog()
{	
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	OBJECT_ATTRIBUTES  objAttr = { 0 };
	BOOLEAN fCreate = FALSE;
	PUNICODE_STRING tmp = NULL;
	UNICODE_STRING tmp_ = { 0 };
	WCHAR LogDirName[1024] = {0};
	UNICODE_STRING uniName = { 0 };
	ULONG buffer_size = 0;
	LogFile = NULL;
	BOOLEAN fl = FALSE;

	RtlZeroMemory(&LogDirName, 1024);
	if (HostPoint_GetStrParams(L"DLPLogPath", &tmp))
	{
		RtlCopyMemory(&LogDirName, tmp->Buffer, tmp->MaximumLength);
		buffer_size = tmp->MaximumLength;
		fl = HostPoint_CreateLogDir(&LogDirName);
	}
	HostPoint_FreeStr(tmp, 1);

	if (!fl)
	{
		RtlZeroMemory(&LogDirName, 1024);
		RtlInitUnicodeString(&tmp_, L"\\SystemRoot\\HostPointDLP.logs");
		RtlCopyMemory(&LogDirName, tmp_.Buffer, tmp_.MaximumLength);
		buffer_size = tmp_.MaximumLength;
		fl = HostPoint_CreateLogDir(&LogDirName);
	}		

	if (!fl) return;

	if (LogDirName[0] != '\0')
	{
		buffer_size += 40;
		uniName.Buffer = NULL;
		uniName.Buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'hps1');
		if (uniName.Buffer == NULL) return 0;
		RtlZeroMemory(uniName.Buffer, buffer_size);
		uniName.Length = uniName.MaximumLength = buffer_size;
		if (NT_SUCCESS(RtlUnicodeStringPrintf(&uniName, L"%ws\\hostpointDLP.log", LogDirName)))
		{
			InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			if (NT_SUCCESS(ZwCreateFile(&LogFile, GENERIC_WRITE, &objAttr, &ioStatusBlock,
				NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
			{
				FILE_STANDARD_INFORMATION StandardInfo = { 0 };
				if (NT_SUCCESS(ZwQueryInformationFile(LogFile, &ioStatusBlock, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)))
				{
					FILE_POSITION_INFORMATION position = { 0 };
					position.CurrentByteOffset.QuadPart = StandardInfo.EndOfFile.LowPart;
					if (NT_SUCCESS(ZwSetInformationFile(LogFile, &ioStatusBlock, &position, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation)))
					{
						fCreate = TRUE;
					}
				}
			}
			if (!fCreate)
			{
				if (LogFile != NULL) ZwClose(LogFile);
				LogFile = NULL;
			}
		}
		if (uniName.Buffer != NULL) ExFreePoolWithTag(uniName.Buffer, 'hps1');
	}
	return;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_AllocateStr(_Inout_ PUNICODE_STRING str)
{
	PAGED_CODE();

	str->Buffer = NULL;
	str->Buffer = ExAllocatePoolWithTag(NonPagedPool, str->MaximumLength, 'Sncs');

	if (str->Buffer == NULL)
	{
		return FALSE;
	}
	str->Length = 0;
	RtlZeroMemory(str->Buffer, str->MaximumLength);
	return TRUE;
}
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_FreeStr(_Inout_ PUNICODE_STRING str,IN ULONG strcount)
{
	PAGED_CODE();
	
	if (str == NULL) return;
	while (strcount > 0)
	{
		strcount--;
		if (((PUNICODE_STRING)(str + strcount)) != NULL)
		{
			if (((PUNICODE_STRING)(str + strcount))->Buffer != NULL)
			{
				ExFreePoolWithTag(((PUNICODE_STRING)(str + strcount))->Buffer, 'Sncs');
				((PUNICODE_STRING)(str + strcount))->Buffer = NULL;
			}
			((PUNICODE_STRING)(str + strcount))->Length = 0;
			((PUNICODE_STRING)(str + strcount))->MaximumLength = 0;
			((PUNICODE_STRING)(str + strcount))->Buffer = NULL;
		}		
	}
	if (str != NULL)
	{
		ExFreePoolWithTag(str, 'Sncs');
	}
	str = NULL;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_CmpStr(_In_ PUNICODE_STRING str1, _In_ PUNICODE_STRING str2, _In_ ULONG strcount)
{
	PAGED_CODE();
	
	if (strcount <= 0) return FALSE;
	if (str1 == NULL || str2 == NULL) return FALSE;
	if (str1->Length <= 0 || str2->Length <= 0)	return FALSE;

	for (ULONG count = 0; count < strcount; count++)
	{
		if (RtlCompareUnicodeString(str1, str2 + count, TRUE) == 0)
		{
			return TRUE;
		} 
	}
	return FALSE;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetStrParams(IN PCWSTR value, IN OUT PUNICODE_STRING *str)
{
	OBJECT_ATTRIBUTES attributes = { 0 };
	HANDLE hKey = NULL;
	UNICODE_STRING ValueName = {0};
	UNICODE_STRING KeyName = {0};
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN fl = FALSE;
	PUNICODE_STRING val = NULL;
	*str = NULL;
	
	RtlInitUnicodeString(&KeyName, HOSTPOINT_REG_KEY_NAME);
	InitializeObjectAttributes(&attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &attributes);
	if (NT_SUCCESS(status))
	{
		RtlInitUnicodeString(&ValueName, value);
		status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, NULL, 0, &valueLength);
		if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
		{
			KdPrint(("[HostPoint]: Error GetValue from - %ws\n", value));
		}
		else
		{
			valueBuffer = ExAllocatePoolWithTag(NonPagedPool, valueLength, 'Rncs');
			if (valueBuffer != NULL)
			{
				RtlZeroMemory(valueBuffer, valueLength);
				status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, valueBuffer, valueLength, &valueLength);
				if (NT_SUCCESS(status) && valueBuffer->Type == REG_SZ && valueBuffer->DataLength > 0)
				{	
					*str = ExAllocatePoolWithTag(PagedPool, sizeof(UNICODE_STRING), 'Sncs');
					if (*str != NULL)
					{						
						val = *str;
						val->Length = val->MaximumLength = (USHORT)valueBuffer->DataLength;
						if (val->Length >0 && HostPoint_AllocateStr(val))
						{							
							RtlCopyMemory(val->Buffer, valueBuffer->Data, val->MaximumLength);
							if (val->Buffer[0] != '\0')
							{
								fl = TRUE;
								KdPrint(("[HostPoint]: GetValue from - %ws completed\n", value));
							}
						} else
						    HostPoint_FreeStr(*str, 0);
					}			
				}
				else
				{
					KdPrint(("[HostPoint]: Error GetValue from - %ws\n", value));
				}
				ExFreePoolWithTag(valueBuffer, 'Rncs');				
				valueBuffer = NULL;
			}
			else
				KdPrint(("[HostPoint]: Error AllocateMemory for value - %ws\n", value));
		}
	}
	else
		KdPrint(("[HostPoint]: Error OpenKey %ws\n", KeyName.Buffer));
	if (hKey != NULL) ZwClose(hKey);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetDwordParams(IN PCWSTR value, IN OUT DWORD *param)
{
	OBJECT_ATTRIBUTES attributes = { 0 };
	HANDLE hKey = NULL;
	UNICODE_STRING ValueName = {0};
	UNICODE_STRING KeyName = {0};
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN fl = FALSE;

	*param = 0;

	RtlInitUnicodeString(&KeyName, HOSTPOINT_REG_KEY_NAME);
	InitializeObjectAttributes(&attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &attributes);
	if (NT_SUCCESS(status))
	{
		RtlInitUnicodeString(&ValueName, value);
		status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, NULL, 0, &valueLength);
		if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
		{
			KdPrint(("[HostPoint]: Error GetValue from - %ws\n",value));
		}
		else
		{
			valueBuffer = ExAllocatePoolWithTag(NonPagedPool, valueLength, 'Rncs');
			if (valueBuffer != NULL)
			{
				RtlZeroMemory(valueBuffer, valueLength);
				status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, valueBuffer, valueLength, &valueLength);
				if (NT_SUCCESS(status) && valueBuffer->Type == REG_DWORD && valueBuffer->DataLength > 0)
				{
					*param = (LONGLONG)(*(PULONG)valueBuffer->Data);
					KdPrint(("[HostPoint]: GetValue from - %ws completed\n",value));
					fl = TRUE;
				}
				else
				{
					KdPrint(("[HostPoint]: Error GetValue from - %ws\n", value));
				}
				ExFreePoolWithTag(valueBuffer, 'Rncs');
				valueBuffer = NULL;
			}
			else
			{
				KdPrint(("[HostPoint]: Error AllocateMemory for %ws\n", value));
			}
       }
	}
	else
	{
		KdPrint(("[HostPoint]: Error OpenKey - HostPoint_GetDWORDParams\n"));
	}
	if (hKey != NULL) ZwClose(hKey);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_GetMultiStrParams(IN PCWSTR value, IN OUT PUNICODE_STRING *str, IN OUT ULONG *strcount)
{
	OBJECT_ATTRIBUTES attributes = {0};
	HANDLE hKey = NULL;
	UNICODE_STRING ValueName = {0};
	UNICODE_STRING KeyName = {0};
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN fl = FALSE;
	PWCHAR ch = NULL;
	SIZE_T length;
	ULONG count;
	PUNICODE_STRING ext = NULL;

	PAGED_CODE();

	*str = NULL; 
	*strcount = 0;

	RtlInitUnicodeString(&KeyName, HOSTPOINT_REG_KEY_NAME);
	InitializeObjectAttributes(&attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &attributes);
	if (NT_SUCCESS(status))
	{
		RtlInitUnicodeString(&ValueName, value);
		status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, NULL, 0, &valueLength);
		if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
		{
			KdPrint(("[HostPoint]: Error GetValue from - %ws\n", value));
		}
		else 
		{
			valueBuffer = ExAllocatePoolWithTag(NonPagedPool, valueLength, 'Rncs');
			if (valueBuffer != NULL)
			{
				RtlZeroMemory(valueBuffer, valueLength);
				status = ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, valueBuffer, valueLength, &valueLength);
				if (NT_SUCCESS(status) && valueBuffer->Type == REG_MULTI_SZ && valueBuffer->DataLength > 0)
				{
					ch = (PWCHAR)(valueBuffer->Data);
					count = 0;
					while (*ch != '\0')
					{
						ch = ch + wcslen(ch) + 1;
						count++;
						if (count > 5000)
						{
							count = 0;
							break;
						}
					}
					if (count > 0)
					{
						*str = ExAllocatePoolWithTag(PagedPool, count * sizeof(UNICODE_STRING), 'Sncs');
						if (*str != NULL)
						{
							ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
							ext = *str;
							while ((*strcount) < count)
							{
									length = wcslen(ch) * sizeof(WCHAR);
									ext->MaximumLength = (USHORT)length;
									if (!HostPoint_AllocateStr(ext))
									{
										HostPoint_FreeStr(*str, (*strcount));
										break;
									} 
									ext->Length = (USHORT)length;
									RtlCopyMemory(ext->Buffer, ch, length);	
									ch = ch + length / sizeof(WCHAR)+1;									
									(*strcount)++;
									ext++;
							}
							if ((*strcount) == count)
							{
								fl = TRUE;
								KdPrint(("[HostPoint]: GetValue from - %ws completed\n", value));
							}
						}
						else
						{
							KdPrint(("[HostPoint]: Error AllocateMemory for value - %ws\n", value));
						}
					}
					else
					{
						KdPrint(("[HostPoint]: Value  - %ws is empty\n", value));
					}
				}
				else
				{
					KdPrint(("[HostPoint]: Error GetValue from - %ws\n", value));
				}
				ExFreePoolWithTag(valueBuffer, 'Rncs');
				valueBuffer = NULL;				
			}
			else
			{
				KdPrint(("[HostPoint]: Error AllocateMemory for value - %ws\n", value));
			}
		} 
	}
	else
	{
		KdPrint(("[HostPoint]: Error OpenKey %ws\n", KeyName.Buffer));
	}
	if (hKey != NULL) ZwClose(hKey);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_IsDeniedProcess(IN PUNICODE_STRING processlist, IN ULONG listcount)
{
	ULONG returnedLength;
	PVOID buffer = NULL;
	BOOLEAN fl = FALSE;

	PAGED_CODE();

	if (listcount <= 0)	return fl;

	if (NULL == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName = {0};

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == ZwQueryInformationProcess)
		{
			KdPrint(("[HostPoint]: Cannot resolve ZwQueryInformationProcess\n"));
			return FALSE;
		}
	}
		
	if (STATUS_INFO_LENGTH_MISMATCH != ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, NULL, 0, &returnedLength)) 
	{ return FALSE; }

	if ((returnedLength - sizeof(UNICODE_STRING)) <= 0)
	{
		return FALSE;
	}
	buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');
	if (NULL == buffer) {  return FALSE; }
	if (NT_SUCCESS(ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, buffer, returnedLength, &returnedLength)))
	{		
		ANSI_STRING ansiStr;
		ansiStr.Buffer = NULL;
		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiStr, (PUNICODE_STRING)buffer, TRUE)))
		{	
			int j;
			for (j = ansiStr.Length - 1; j > 0; j--)
			{
				if (ansiStr.Buffer[j] == '\\')
					break;
			}
			if (j > 0 && ansiStr.Length > 0)
			{
				ANSI_STRING name;
				name.Buffer = NULL;
				returnedLength = ansiStr.Length - (j + 1);
				name.Buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'hosD');
				if (name.Buffer != NULL)
				{
					RtlZeroMemory(name.Buffer, returnedLength);
					name.Length = name.MaximumLength = returnedLength;
					RtlCopyMemory(name.Buffer, &ansiStr.Buffer[j + 1], returnedLength);

					UNICODE_STRING  tmpUnicodeString = { 0 };
					tmpUnicodeString.Buffer = NULL;
					if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&tmpUnicodeString, &name, TRUE)))
					{
						if (HostPoint_CmpStr(&tmpUnicodeString, processlist, listcount))
						{
							HostPoint_WriteLog("FileDLP found a prohibited process - ", &tmpUnicodeString);
							fl = TRUE;
						}
					}
					if (tmpUnicodeString.Buffer != NULL) RtlFreeUnicodeString(&tmpUnicodeString);
					ExFreePool(name.Buffer);
				}
			}			
		}
		if (ansiStr.Buffer != NULL)
			RtlFreeAnsiString(&ansiStr);
	}
	ExFreePool(buffer);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
BOOLEAN HostPoint_IsDeniedUser(IN PUNICODE_STRING userlist, IN ULONG listcount)
{
	TOKEN_USER *user = NULL;
	HANDLE token = NULL;
	NTSTATUS status;
	unsigned long len;
	BOOLEAN fl = FALSE;
	
	if (listcount <= 0)	return fl;
	
	if ((status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_READ, TRUE, OBJ_KERNEL_HANDLE, &token)) != STATUS_SUCCESS)
	{
		status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_READ, OBJ_KERNEL_HANDLE, &token);
	}
	if (!NT_SUCCESS(status)) return fl;
	status = ZwQueryInformationToken(token, TokenUser, NULL, 0, &len);
	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
	{
	}
	else
	{
		if ((user = ExAllocatePoolWithTag(NonPagedPool, len, 'hp1t')))
		{			
			if ((status = ZwQueryInformationToken(token, TokenUser, user, len, &len)) == STATUS_SUCCESS)
			{
				if (user->User.Sid != NULL)
				{
					UNICODE_STRING NameBuffer = {0};
					NameBuffer.Buffer = NULL;
					if (NT_SUCCESS(RtlConvertSidToUnicodeString(&NameBuffer, user->User.Sid, TRUE)))
					{
						if (HostPoint_CmpStr(&NameBuffer, userlist, listcount))
						{
							KdPrint(("[HostPoint]: SID - %ws\n", NameBuffer.Buffer));
							HostPoint_WriteLog("FileDLP found a prohibited user SID - ", &NameBuffer);
							fl = TRUE;
						}						
					}
					if (NameBuffer.Buffer != NULL)
						ExFreePool(NameBuffer.Buffer);
				}
			}
			ExFreePoolWithTag(user, 'hp1t');
		} 			
	}	
	ZwClose(token);
	return fl;
}
//---------------------------------------------------------------------------------------------------------
ULONG HostPoint_DriveType(IN PFLT_VOLUME Volume)
{
	PAGED_CODE();
	ULONG fl = 0;
	if (Volume != NULL)
	{
		ULONG returnedLength;
		PIRP NewIrp = NULL;
		STORAGE_PROPERTY_QUERY Query;
		PSTORAGE_DEVICE_DESCRIPTOR Descriptor = NULL;
		KEVENT WaitEvent;
		IO_STATUS_BLOCK IoStatus;
		PDEVICE_OBJECT DiskDeviceObj = NULL;

		Query.PropertyId = StorageDeviceProperty;
		Query.QueryType = PropertyStandardQuery;

		KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
		Descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPool, sizeof(STORAGE_DEVICE_DESCRIPTOR)+512, 'hdlp');

		NTSTATUS status = FltGetDiskDeviceObject(Volume, &DiskDeviceObj);
		if (NT_SUCCESS(status) && Descriptor != NULL)
		{
			NewIrp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY, DiskDeviceObj, (PVOID)&Query, sizeof(STORAGE_PROPERTY_QUERY),
				                                  (PVOID)Descriptor, sizeof(STORAGE_DEVICE_DESCRIPTOR)+512, FALSE, &WaitEvent, &IoStatus);
			if (NewIrp != NULL)
			{
				status = IoCallDriver(DiskDeviceObj, NewIrp);
				if (status == STATUS_PENDING)
				{
					status = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
					status = IoStatus.Status;
				}
				if (NT_SUCCESS(status))				
				{	
					switch (Descriptor->BusType)
					{
					case BusTypeUsb:
					case BusType1394:
					case BusTypeSd:
					case BusTypeUnknown:
						fl = 1;
						break;
					case BusTypeAta:
					case BusTypeSata:
						fl = 2;
						break;
					}					
				}
			}
		}
		if (Descriptor != NULL) ExFreePoolWithTag(Descriptor, 'hdlp');
		if (DiskDeviceObj != NULL) ObDereferenceObject(DiskDeviceObj);
	}
	return fl;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS HostPoint_FilterLoad(IN PCFLT_RELATED_OBJECTS  FltObjects, IN FLT_INSTANCE_SETUP_FLAGS  Flags, IN DEVICE_TYPE  VolumeDeviceType, IN FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	switch (VolumeDeviceType)
	{
	case FILE_DEVICE_NETWORK_FILE_SYSTEM:return STATUS_FLT_DO_NOT_ATTACH;
	case FILE_DEVICE_CD_ROM_FILE_SYSTEM: return STATUS_FLT_DO_NOT_ATTACH;
	case FILE_DEVICE_DISK_FILE_SYSTEM:
	{
		
		break;
	}
	default: return STATUS_FLT_DO_NOT_ATTACH;
	}
	return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS HostPoint_FilterUnload(IN FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS HostPoint_FilePreCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	PFILE_OBJECT FileObject = NULL;

	PAGED_CODE();

	if (FLT_IS_FS_FILTER_OPERATION(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (FltObjects->FileObject != NULL && Data != NULL && Data->Iopb != NULL && Data->Iopb->TargetFileObject != NULL)
	{
		if (!NT_SUCCESS(Data->IoStatus.Status) || STATUS_REPARSE == Data->IoStatus.Status)	return FLT_PREOP_SUCCESS_NO_CALLBACK;

		FileObject = Data->Iopb->TargetFileObject;
		if (FileObject != NULL && Data->Iopb->MajorFunction == IRP_MJ_CREATE) 
		{
			PFLT_FILE_NAME_INFORMATION pFileNameInformation = NULL;
			if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &pFileNameInformation)))
			{
				if (pFileNameInformation != NULL)
				{					
					if (NT_SUCCESS(FltParseFileNameInformation(pFileNameInformation)))
					{												
						if (Data->Iopb->Parameters.Create.SecurityContext != NULL)
						{
							int flag_on = 0;
							if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_WRITE_DATA))
								flag_on = 1;
						
							if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_EXECUTE))		
								flag_on = 2;
	
							if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, DELETE))
								flag_on = 3;

							if (flag_on > 0)								
							{								
								BOOLEAN lock = FALSE;

								switch (HostPoint_DriveType(FltObjects->Volume))
								{
									case 1: // Если USB Устройство
									{
												switch (flag_on)
												{  
														case 1: // Открытие файла для записи или редактирования
															if (FileDLP.TotalLockUSB == 1)
															{
																lock = TRUE;
																HostPoint_WriteLog("FileDLP have flag - Lock All create/write/change operation for USB storage devices", NULL);
															}
															else
															{
																if (HostPoint_CmpStr(&pFileNameInformation->Extension, FileDLP.HostPointExtensionsUSB, FileDLP.HostPointExtensionCountUSB))
																{
																	HostPoint_WriteLog("FileDLP found a prohibited file extension for USB storage devices - ", &pFileNameInformation->Extension);
																	lock = TRUE;
																}
																if (HostPoint_IsDeniedProcess(FileDLP.HostPointProcessesUSB, FileDLP.HostPointProcessesCountUSB))
																	lock = TRUE;
																if (HostPoint_IsDeniedUser(FileDLP.HostPointUsersUSB, FileDLP.HostPointUsersCountUSB))
																	lock = TRUE;
															}
															break;
														case 2: // Открытие файла для запуска (Execute)
															if (FileDLP.LockProcExecuteUSB == 1)
															{
																lock = TRUE;
																HostPoint_WriteLog("FileDLP have flag - Lock All execute program operation for USB storage devices", NULL);
															}
															else
															{
																if (HostPoint_IsDeniedProcess(FileDLP.HostPointProcessesLEUSB, FileDLP.HostPointProcessesLECountUSB))
																	lock = TRUE;
																if (HostPoint_IsDeniedUser(FileDLP.HostPointUsersLEUSB, FileDLP.HostPointUsersLECountUSB))
																	lock = TRUE;
															}
															break;
														case 3: // Удаление файла
															// запрещено удалять пользователям
															// запрещено удалять программам
															// запрещено вообще удалять любые файлы
															// запрещено удалять файлы с определенным расширением
															break;
												}											
											break;									
									} // Локальный диск
									case 2:
									{
											  switch (flag_on) // Создание файла или редактирование
											  {
														  case 1:
															  if (HostPoint_CmpStr(&pFileNameInformation->Extension, FileDLP.HostPointExtensionsLocal, FileDLP.HostPointExtensionCountLocal))
															  {
																  HostPoint_WriteLog("FileDLP found a prohibited file extension for Local storage devices - ", &pFileNameInformation->Extension);
																  lock = TRUE;
															  }
															  if (HostPoint_IsDeniedProcess(FileDLP.HostPointProcessesLocal, FileDLP.HostPointProcessesCountLocal))
															  {
																  lock = TRUE;
															  }
															  if (HostPoint_IsDeniedUser(FileDLP.HostPointUsersLocal, FileDLP.HostPointUsersCountLocal))
															  {
																  lock = TRUE;
															  }
															  break;
														  case 2: // запуск файла или редактирвоание
															  if (FileDLP.LockProcExecuteLocal == 1)
															  {
																  if (HostPoint_IsDeniedProcess(FileDLP.HostPointProcessesLELocal, FileDLP.HostPointProcessesLECountLocal))
																	  lock = TRUE;
																  if (HostPoint_IsDeniedUser(FileDLP.HostPointUsersLELocal, FileDLP.HostPointUsersLECountLocal))
																	  lock = TRUE;
															  }
															  break;
														  case 3: //Удаление файла
															  // запрещено удалять пользователям
															  // запрещено удалять программам
															  // запрещено вообще удалять любые файлы
															  // запрещено удалять файлы с определенным расширением
															  // Запрещено удалять файлы в определенное время
															  break;
											  }											
											break;
									}
								}
								if (lock)
								{									
									KdPrint(("[HostPoint]: locked - %ws\n", pFileNameInformation->Name.Buffer));
									HostPoint_WriteLog("FileDLP lock - ", &pFileNameInformation->Name);
									Data->IoStatus.Status = STATUS_ACCESS_DENIED;
									Data->IoStatus.Information = 0;
									FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);									
									status = FLT_PREOP_COMPLETE;
								}
							}
						}	
					} 
					FltReleaseFileNameInformation(pFileNameInformation);
				}
			}
		}
	}
	return status;
}
//---------------------------------------------------------------------------------------------------------
FLT_POSTOP_CALLBACK_STATUS HostPoint_FilePostCreate(IN OUT PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags)
{
	 UNREFERENCED_PARAMETER(CompletionContext);
	 UNREFERENCED_PARAMETER(Data);
	 UNREFERENCED_PARAMETER(FltObjects);
	 UNREFERENCED_PARAMETER(Flags);

     return FLT_POSTOP_FINISHED_PROCESSING;
}
//---------------------------------------------------------------------------------------------------------
VOID HostPoint_OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	if (pFilter != NULL) FltUnregisterFilter(pFilter);	
	HostPoint_FreeStr(FileDLP.HostPointExtensionsUSB, FileDLP.HostPointExtensionCountUSB);
	HostPoint_FreeStr(FileDLP.HostPointProcessesUSB, FileDLP.HostPointProcessesCountUSB);
	HostPoint_FreeStr(FileDLP.HostPointUsersUSB, FileDLP.HostPointUsersCountUSB);
	HostPoint_FreeStr(FileDLP.HostPointExtensionsLocal, FileDLP.HostPointExtensionCountLocal);
	HostPoint_FreeStr(FileDLP.HostPointProcessesLocal, FileDLP.HostPointProcessesCountLocal);
	HostPoint_FreeStr(FileDLP.HostPointUsersLocal, FileDLP.HostPointUsersCountLocal);	
	HostPoint_FreeStr(FileDLP.HostPointProcessesLEUSB, FileDLP.HostPointProcessesLECountUSB);		
	HostPoint_FreeStr(FileDLP.HostPointUsersLEUSB, FileDLP.HostPointUsersLECountUSB);	
	HostPoint_FreeStr(FileDLP.HostPointProcessesLELocal, FileDLP.HostPointProcessesLECountLocal);		
	HostPoint_FreeStr(FileDLP.HostPointUsersLELocal, FileDLP.HostPointUsersLECountLocal);
	HostPoint_WriteLog("FileDLP Module - Stopped.", NULL);
	HostPoint_WriteLog("-------------------------------------------------------------------------------------------", NULL);
	if (LogFile != NULL) ZwClose(LogFile);
	KdPrint(("[HostPoint]: Stopped\n"));

}
//--------------------------------------------------------------------------------------------------------- 
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING theRegistryPath )
{
  	UNREFERENCED_PARAMETER(theRegistryPath);

	NTSTATUS status;

	DriverObject->DriverUnload = HostPoint_OnUnload;
	pFilter = NULL;

	HostPoint_InitLog();

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &pFilter);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(pFilter);
		if (NT_SUCCESS(status))
		{			
			status = STATUS_UNSUCCESSFUL;
			if (HostPoint_GetDwordParams(L"GlobalLockUSB", &FileDLP.TotalLockUSB))
				status = STATUS_SUCCESS;		
			if (HostPoint_GetDwordParams(L"LockProcExecuteLocal", &FileDLP.LockProcExecuteLocal))
				status = STATUS_SUCCESS;	
			if (HostPoint_GetDwordParams(L"LockProcExecuteUSB", &FileDLP.LockProcExecuteUSB))
				status = STATUS_SUCCESS;	
			if (HostPoint_GetMultiStrParams(L"FileExtensionsLockUSB", &FileDLP.HostPointExtensionsUSB, &FileDLP.HostPointExtensionCountUSB))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"ProcNameLockUSB", &FileDLP.HostPointProcessesUSB, &FileDLP.HostPointProcessesCountUSB))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"UserNameLockUSB", &FileDLP.HostPointUsersUSB, &FileDLP.HostPointUsersCountUSB))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"FileExtensionsLockLocal", &FileDLP.HostPointExtensionsLocal, &FileDLP.HostPointExtensionCountLocal))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"ProcNameLockLocal", &FileDLP.HostPointProcessesLocal, &FileDLP.HostPointProcessesCountLocal))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"UserNameLockLocal", &FileDLP.HostPointUsersLocal, &FileDLP.HostPointUsersCountLocal))
				status = STATUS_SUCCESS;			
			if (HostPoint_GetMultiStrParams(L"ProcNameLockExecUSB", &FileDLP.HostPointProcessesLEUSB, &FileDLP.HostPointProcessesLECountUSB))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"UserNameLockExecUSB", &FileDLP.HostPointUsersLEUSB, &FileDLP.HostPointUsersLECountUSB))
				status = STATUS_SUCCESS;			
			if (HostPoint_GetMultiStrParams(L"ProcNameLockExecLocal", &FileDLP.HostPointProcessesLELocal, &FileDLP.HostPointProcessesLECountLocal))
				status = STATUS_SUCCESS;
			if (HostPoint_GetMultiStrParams(L"UserNameLockExecLocal", &FileDLP.HostPointUsersLELocal, &FileDLP.HostPointUsersLECountLocal))
				status = STATUS_SUCCESS;						
			if (status == STATUS_SUCCESS)
			{
				HostPoint_WriteLog("-------------------------------------------------------------------------------------------", NULL);
				HostPoint_WriteLog("FileDLP Module - Started.", NULL);
				KdPrint(("[HostPoint]: FileDLP Module Started.\n"));
				return status;
			}
			else
			{
				HostPoint_WriteLog("FileDLP Module not started. ERROR GetConfigurationData.", NULL);
				KdPrint(("[HostPoint]:FileDLP Module not started. ERROR GetConfigurationData.\n"));
			}
		}
		else
		{
			KdPrint(("[HostPoint]: FileDLP Module not started. ERROR FltStartFiltering - %08x.\n", status));
			HostPoint_WriteLog("FileDLP Module not started. ERROR FltStartFiltering.", NULL);
		}
	}
	else
	{
		KdPrint(("[HostPoint]: FileDLP Module not started. ERROR FltRegisterFilter - %08x.\n", status));
		HostPoint_WriteLog("FileDLP Module not started. ERROR FltRegisterFilter.", NULL);
	}

	if (pFilter != NULL) FltUnregisterFilter(pFilter);
	pFilter = NULL;
	
	return status;
}