#pragma once

enum PROCESS_NOTIFY_TYPE : UINT32 {
	PsSetCreateProcessNotifyRoutine_Default = 0,
	PsSetCreateProcessNotifyRoutine_Remove,

	PsSetCreateProcessNotifyRoutineEx_Default = 2,
	PsSetCreateProcessNotifyRoutineEx_Remove,

	PsSetCreateProcessNotifyRoutineEx2_Default = 6,
	PsSetCreateProcessNotifyRoutineEx2_Remove,
};

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;