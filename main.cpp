#include <ntddk.h>
#include "defines.h"

PDRIVER_OBJECT GDriverObject;
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

typedef EX_RUNDOWN_REF* (__fastcall* tExReferenceCallBackBlock)(void*);
tExReferenceCallBackBlock ExReferenceCallBackBlock;

typedef void(__fastcall* tExDereferenceCallBackBlock)(void*, EX_RUNDOWN_REF*);
tExDereferenceCallBackBlock ExDereferenceCallBackBlock;

RTL_RUN_ONCE* PspCreateProcessNotifyRoutine;

PLDR_DATA_TABLE_ENTRY FindKernelModuleByName(PUNICODE_STRING ModuleName) {
	PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)GDriverObject->DriverSection;
	while (Entry->InLoadOrderLinks.Flink != GDriverObject->DriverSection) {
		if (RtlCompareUnicodeString(ModuleName, &Entry->BaseDllName, true) == 0)
			return Entry;
		Entry = (PLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}
	return 0;
}

PLDR_DATA_TABLE_ENTRY FindKernelModuleByAddress(PVOID Address) {
	PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)GDriverObject->DriverSection;
	while (Entry->InLoadOrderLinks.Flink != GDriverObject->DriverSection) {
		if (Address >= Entry->DllBase && Address <= (PVOID)((UINT64)Entry->DllBase + Entry->SizeOfImage))
			return Entry;
		Entry = (PLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}
	return 0;
}

void* SignatureScan(void* Memory, size_t Limit, const char* Signature, const char* Mask) {
	size_t SignatureSize = strlen(Signature);
	if (SignatureSize > strlen(Mask))
		return 0;
	for (int i = 0; i < Limit; i++) {
		for (int a = 0; a < SignatureSize; a++) {
			if (((char*)Memory)[i + a] == Signature[a] || Mask[a] == '?') {
				if (a == (SignatureSize - 1))
					return (void*)((UINT64)Memory + i);
			}
			else
				break;
		}
	}
	return 0;
}

bool InitFunctions(PLDR_DATA_TABLE_ENTRY Ntoskrnl) {
	ExReferenceCallBackBlock = (tExReferenceCallBackBlock)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x48\x89\x5C\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF9\x0F\x0D\x09\x48\x8B\x19\xF6\xC3\x0F", "xxxxxxxxxxxxxxxxxxxxxx");
	if (!ExReferenceCallBackBlock)
		return false;

	ExDereferenceCallBackBlock = (tExDereferenceCallBackBlock)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x48\x83\xEC\x28\x4C\x8B\xCC\x0F\x0D\x09\x48\x8B\x01\x4C\x8B\xC0\x4C\x33\xC2\x49\x83\xF8\x0F", "xxxxxx?xxxxxxxxxxxxxxxx");
	if (!ExDereferenceCallBackBlock)
		return false;

	PspCreateProcessNotifyRoutine = (RTL_RUN_ONCE*)SignatureScan(Ntoskrnl->DllBase, Ntoskrnl->SizeOfImage,
		"\x4C\x8D\x2D\xCC\xCC\xCC\xCC\x48\x8D\x0C\xDD\x00\x00\x00\x00", "xxx????xxxxxxxx");
	if (!PspCreateProcessNotifyRoutine)
		return false;

	PspCreateProcessNotifyRoutine = (RTL_RUN_ONCE*)((UINT64)PspCreateProcessNotifyRoutine +
		*(UINT32*)((UINT64)PspCreateProcessNotifyRoutine + 0x3) + 0x7);

	if (!MmIsAddressValid(PspCreateProcessNotifyRoutine))
		return false;

	return true;
}

bool SetupCreateProcessNotifyHook(PUNICODE_STRING ModuleName, PROCESS_NOTIFY_TYPE NotifyType,
	PVOID Hook, PVOID& Original)
{
	for (int i = 0; i < 0x40; i++) {
		EX_RUNDOWN_REF* CurrentCallback = ExReferenceCallBackBlock(&PspCreateProcessNotifyRoutine[i]);
		if (!CurrentCallback)
			continue;

		UINT32 CallbackType = *(UINT32*)((UINT64)CurrentCallback + 0x10);
		PVOID* CallbackAddress = (PVOID*)((UINT64)CurrentCallback + 0x8);
		if (CallbackType != NotifyType || !MmIsAddressValid(*CallbackAddress))
			goto DereferenceCallBackBlock;

		PLDR_DATA_TABLE_ENTRY Module = FindKernelModuleByAddress(*CallbackAddress);
		if (!Module || RtlCompareUnicodeString(ModuleName, &Module->BaseDllName, true) != 0)
			goto DereferenceCallBackBlock;

		DbgPrint("Callback function: %llx (Type: %i) (%ws)\n", (UINT64)*CallbackAddress, CallbackType, Module->BaseDllName.Buffer);

		Original = *CallbackAddress;
		*CallbackAddress = Hook;

	DereferenceCallBackBlock:
		ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine[i], CurrentCallback);
		if (*CallbackAddress == Hook)
			return true;
	}
	return false;
}

PCREATE_PROCESS_NOTIFY_ROUTINE_EX CreateProcessNotifyOriginal;
void CreateProcessNotifyHook(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
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