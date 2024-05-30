#include <ntddk.h>
#include "defines.h"

PDRIVER_OBJECT GDriverObject;
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

tExReferenceCallBackBlock ExReferenceCallBackBlock;
tExDereferenceCallBackBlock ExDereferenceCallBackBlock;

PEX_CALLBACK PspCreateProcessNotifyRoutine;

PLDR_DATA_TABLE_ENTRY FindKernelModuleByName(PUNICODE_STRING ModuleName) {
	PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)GDriverObject->DriverSection;
	while (Entry->InLoadOrderLinks.Flink != GDriverObject->DriverSection) {
		if (RtlCompareUnicodeString(ModuleName, &Entry->BaseDllName, true) == 0)
			return Entry;
		Entry = (PLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}
	return NULL;
}

PLDR_DATA_TABLE_ENTRY FindKernelModuleByAddress(PVOID Address) {
	PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)GDriverObject->DriverSection;
	while (Entry->InLoadOrderLinks.Flink != GDriverObject->DriverSection) {
		if (Address >= Entry->DllBase && Address <= (PVOID)((UINT64)Entry->DllBase + Entry->SizeOfImage))
			return Entry;
		Entry = (PLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}
	return NULL;
}

PVOID SignatureScan(PVOID Mem, UINT32 Limit, CONST CHAR* Pattern, CONST CHAR* Mask, UINT32 Size) {
	for (UINT32 i = 0; i < Limit - Size; i++) {
		for (UINT32 a = 0; a < Size; a++) {
			if (Mask[a] == '?' || ((CHAR*)Mem)[i + a] == Pattern[a]) {
				if (a == Size - 1)
					return &((CHAR*)Mem)[i];
			}
			else
				break;
		}
	}

	return NULL;
}

BOOLEAN InitFunctions(PLDR_DATA_TABLE_ENTRY Ntoskrnl) {
	ExReferenceCallBackBlock = (tExReferenceCallBackBlock)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x48\x89\x5C\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF9\x0F\x0D\x09\x48\x8B\x19\xF6\xC3\x0F", "xxxxxxxxxxxxxxxxxxxxxx", 22);
	if (!ExReferenceCallBackBlock)
		return FALSE;

	ExDereferenceCallBackBlock = (tExDereferenceCallBackBlock)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x48\x83\xEC\x28\x4C\x8B\xCC\x0F\x0D\x09\x48\x8B\x01\x4C\x8B\xC0\x4C\x33\xC2\x49\x83\xF8\x0F", "xxxxxx?xxxxxxxxxxxxxxxx", 23);
	if (!ExDereferenceCallBackBlock)
		return FALSE;

	PspCreateProcessNotifyRoutine = (PEX_CALLBACK)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x4C\x8D\x2D\xCC\xCC\xCC\xCC\x48\x8D\x0C\xDD\x00\x00\x00\x00", "xxx????xxxxxxxx", 15);
	if (!PspCreateProcessNotifyRoutine)
		return FALSE;

	PspCreateProcessNotifyRoutine = (PEX_CALLBACK)((UINT64)PspCreateProcessNotifyRoutine +
		*(UINT32*)((UINT64)PspCreateProcessNotifyRoutine + 0x3) + 0x7);

	if (!MmIsAddressValid(PspCreateProcessNotifyRoutine))
		return FALSE;

	return TRUE;
}

BOOLEAN SetupCreateProcessNotifyHook(PUNICODE_STRING ModuleName, PROCESS_NOTIFY_TYPE NotifyType,
	PVOID Hook, PVOID& Original)
{
	for (int i = 0; i < 0x40; i++) {
		PEX_CALLBACK_ROUTINE_BLOCK CurrentCallback = ExReferenceCallBackBlock(&PspCreateProcessNotifyRoutine[i]);
		if (!CurrentCallback)
			continue;

		UINT32 CallbackType = (UINT32)CurrentCallback->Context;
		if (CallbackType != NotifyType || !MmIsAddressValid(CurrentCallback->Function))
			goto DereferenceCallBackBlock;

		PLDR_DATA_TABLE_ENTRY Module = FindKernelModuleByAddress(CurrentCallback->Function);
		if (!Module || RtlCompareUnicodeString(ModuleName, &Module->BaseDllName, true) != 0)
			goto DereferenceCallBackBlock;

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"Callback function: 0x%llX (Type: %i) (%ws)\n", CurrentCallback->Function, CallbackType, Module->BaseDllName.Buffer);

		Original = CurrentCallback->Function;
		CurrentCallback->Function = (PEX_CALLBACK_FUNCTION)Hook;

	DereferenceCallBackBlock:
		ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine[i], CurrentCallback);
		if (CurrentCallback->Function == Hook)
			return TRUE;
	}
	return FALSE;
}

PCREATE_PROCESS_NOTIFY_ROUTINE_EX CreateProcessNotifyOriginal;
VOID CreateProcessNotifyHook(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	if (ProcessId == (HANDLE)0x1337)
		return;

	return CreateProcessNotifyOriginal(Process, ProcessId, CreateInfo);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	GDriverObject = DriverObject;
	DriverObject->DriverUnload = DriverUnload;

	UNICODE_STRING NtoskrnlStr = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
	PLDR_DATA_TABLE_ENTRY Ntoskrnl = FindKernelModuleByName(&NtoskrnlStr);

	if (!InitFunctions(Ntoskrnl))
		return STATUS_INVALID_ADDRESS;

	UNICODE_STRING AvastStr = RTL_CONSTANT_STRING(L"aswSP.sys");
	if (!SetupCreateProcessNotifyHook(&AvastStr, PsSetCreateProcessNotifyRoutineEx2_Default,
		CreateProcessNotifyHook, (PVOID&)CreateProcessNotifyOriginal))
		return STATUS_NOT_FOUND;

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
}