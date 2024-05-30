#pragma once

// https://doxygen.reactos.org/dc/d8d/struct__EX__CALLBACK__ROUTINE__BLOCK.html
typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
	EX_RUNDOWN_REF RundownProtect;
	PEX_CALLBACK_FUNCTION Function;
	PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

// https://doxygen.reactos.org/da/dde/struct__EX__FAST__REF.html
typedef struct _EX_FAST_REF {
	union {
		PVOID Object;
		ULONG_PTR RefCnt : 3;
		ULONG_PTR Value;
	};
} EX_FAST_REF, *PEX_FAST_REF;

// https://doxygen.reactos.org/de/db2/struct__EX__CALLBACK.html
typedef struct _EX_CALLBACK {
	EX_FAST_REF RoutineBlock;
} EX_CALLBACK, *PEX_CALLBACK;

// https://doxygen.reactos.org/d1/d6e/ntoskrnl_2ex_2callback_8c.html#a7f04776f362c6cb892759f0200bfde86
typedef PEX_CALLBACK_ROUTINE_BLOCK(__fastcall* tExReferenceCallBackBlock)(PEX_CALLBACK);

// https://doxygen.reactos.org/d1/d6e/ntoskrnl_2ex_2callback_8c.html#ae57f266eb4bb9028bb4bcacc2588cb4a
typedef void(__fastcall* tExDereferenceCallBackBlock)(PEX_CALLBACK, PEX_CALLBACK_ROUTINE_BLOCK);

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