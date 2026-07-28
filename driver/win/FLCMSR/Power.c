/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Power.h"
#include "Power.tmh"
#include "Utility.h"
#include "sgx_lc_msr_public.h"
#include "Key.h"

//static BOOLEAN OwnFLC = FALSE;
sgx_get_launch_support_output_t launch_support_info = { 0 };
SGX_PUBKEYHASH  legacypubKeyHash = { 0 };
// Protects launch_support_info between the registry-change thread (writer)
// and the IOCTL handler (reader), which can run at DISPATCH_LEVEL.
KSPIN_LOCK gLaunchSupportInfoLock;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FLCMSREvtDeviceD0Exit)
#endif // ALLOC_PRAGMA

volatile ULONG *PROCESSOR_MSR_FLAG = NULL;
PKDPC pkdpc = NULL;
PKTHREAD gFLCNotifyRegistryChangeThreadObject = NULL;

#define RET_NOT_EXECUTED 0
#define RET_WROTE_MSR    1
#define RET_NO_FEATURE   2
#define RET_EXCEPTION    3
volatile BOOLEAN gFLCNotifyRegistryChangeThreadStatus = FALSE;
WDFKEY gRegKey = NULL;
HANDLE gRegKeyHandle = NULL;

KDEFERRED_ROUTINE WriteMsrRoutine;
KSTART_ROUTINE FLCMSRNotifyRegistryChangeRoutine;

void WriteMsrRoutine(
    KDPC *Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument2);
    BOOLEAN UsePLEOptIn = !!(SystemArgument1);
    ULONG ret = 0;
    __int64 feature_control = 0;

    try
    {
        feature_control = __readmsr(MSR_IA32_FEATURE_CONTROL);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_UTILITY, "MSR_IA32_FEATURE_CONTROL %llx", feature_control);

        if (feature_control & (1 << 17))
        {
            if (UsePLEOptIn)
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_UTILITY, "Writing MSRs %llx %llx %llx %llx",
                    MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_0, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_1, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_2, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_3);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_0, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_0);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_1, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_1);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_2, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_2);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_3, MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_3);
            }
            else
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_UTILITY, "Writing legacypubKeyHash %llx %llx %llx %llx",
                    legacypubKeyHash.pubKeyHash_Value_0, legacypubKeyHash.pubKeyHash_Value_1, legacypubKeyHash.pubKeyHash_Value_2, legacypubKeyHash.pubKeyHash_Value_3);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_0, legacypubKeyHash.pubKeyHash_Value_0);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_1, legacypubKeyHash.pubKeyHash_Value_1);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_2, legacypubKeyHash.pubKeyHash_Value_2);
                __writemsr(MSR_IA32_SGX_LE_PUBKEYHASH_3, legacypubKeyHash.pubKeyHash_Value_3);
            }
            ret = RET_WROTE_MSR;
        }
        else
        {
            ret = RET_NO_FEATURE;
        }
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        ret = RET_EXCEPTION;
    }

    PROCESSOR_NUMBER group_and_processor = { 0,0,0 };
    KeGetCurrentProcessorNumberEx(&group_and_processor);
    if (PROCESSOR_MSR_FLAG != NULL)
    {
        PROCESSOR_MSR_FLAG[group_and_processor.Group * MAXIMUM_PROC_PER_GROUP + group_and_processor.Number] = ret;
    }
    return;
}

void ReadMsr()
{
    __int64 feature_control = 0;

    try
    {
        feature_control = __readmsr(MSR_IA32_FEATURE_CONTROL);

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_UTILITY, "MSR_IA32_FEATURE_CONTROL %llx", feature_control);

        if (feature_control & (1 << 17))
        {
            legacypubKeyHash.pubKeyHash_Value_0 = __readmsr(MSR_IA32_SGX_LE_PUBKEYHASH_0);
            legacypubKeyHash.pubKeyHash_Value_1 = __readmsr(MSR_IA32_SGX_LE_PUBKEYHASH_1);
            legacypubKeyHash.pubKeyHash_Value_2 = __readmsr(MSR_IA32_SGX_LE_PUBKEYHASH_2);
            legacypubKeyHash.pubKeyHash_Value_3 = __readmsr(MSR_IA32_SGX_LE_PUBKEYHASH_3);
        }
    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_UTILITY, "read msr The Key is %llx %llx %llx %llx",
        legacypubKeyHash.pubKeyHash_Value_0,
        legacypubKeyHash.pubKeyHash_Value_1,
        legacypubKeyHash.pubKeyHash_Value_2,
        legacypubKeyHash.pubKeyHash_Value_3);
    return;
}

static BOOLEAN is_PLE_OPT_IN()
{
    ULONG ulPLEOptIn = 0;

    //Get PLE Opt-In from the Registry
    WDFKEY key;
    NTSTATUS status = WdfDriverOpenParametersRegistryKey(WdfGetDriver(), KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &key);
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! WdfDriverOpenParametersRegistryKey failed %!STATUS!", status);
    }
    else
    {
        DECLARE_CONST_UNICODE_STRING(valueName, SGX_PLE_REGISTRY_OPT_IN_REGISTRY);
        status = WdfRegistryQueryULong(key, &valueName, &ulPLEOptIn);
        if (!NT_SUCCESS(status))
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! WdfRegistryQueryULong failed %!STATUS!", status);
        }
        WdfRegistryClose(key);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "PLE_OPT_IN:0x%x", ulPLEOptIn);

    if (ulPLEOptIn == 1)
        return TRUE;
    else
        return FALSE;
}

static BOOLEAN FLCWriteMSRs(BOOLEAN UsePLEOptIn)
{
    BYTE maximumProcessor = 0;
    BYTE i = 0;
    BYTE count = 0;
    PKDPC tmp_pkdc = NULL;
    USHORT current_group_count;
    USHORT current_group;
    PROCESSOR_NUMBER group_and_processor = { 0,0,0 };
    BOOLEAN result = TRUE;

    // Processors may be dynamically added to a group. The number of groups can increase.
    current_group_count = KeQueryActiveGroupCount();

    for (current_group = 0; current_group < current_group_count; current_group++)
    {
        group_and_processor.Group = current_group;
        // Documentation says it can't be greater than MAXIMUM_PROC_PER_GROUP, which is defined to 64.
        // Type-casting should be OK.
        maximumProcessor = (BYTE)KeQueryActiveProcessorCountEx(current_group);

        if (PROCESSOR_MSR_FLAG == NULL)
        {
            // Allocate for max group count to safely handle CPU hot-add without reallocation.
            USHORT max_group_count = KeQueryMaximumGroupCount();
            PROCESSOR_MSR_FLAG = (ULONG*)ExAllocatePoolZero(NonPagedPoolNx, max_group_count*(MAXIMUM_PROC_PER_GROUP * sizeof(ULONG)), 'flag');
            if (PROCESSOR_MSR_FLAG == NULL)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, " Insufficient memory");
                return FALSE;
            }
        }

        if (pkdpc == NULL)
        {
            USHORT max_group_count = KeQueryMaximumGroupCount();
            pkdpc = (PKDPC)ExAllocatePoolZero(NonPagedPoolNx, max_group_count*(MAXIMUM_PROC_PER_GROUP * sizeof(KDPC)), 'kdpc');
            if (pkdpc == NULL)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, " Insufficient memory");
                ExFreePoolWithTag((PVOID)(ULONG_PTR)PROCESSOR_MSR_FLAG, 'flag');
                PROCESSOR_MSR_FLAG = NULL;
                return FALSE;
            }
            tmp_pkdc = pkdpc;
            // Allocation size (max_group_count * MAXIMUM_PROC_PER_GROUP * sizeof(KDPC))
            // matches loop bound, so PREfast's buffer-overrun warning is a false positive.
#pragma warning(push)
#pragma warning(disable: 6386)
            for (UINT32 j = 0; j < (UINT32)(max_group_count * MAXIMUM_PROC_PER_GROUP); j++, tmp_pkdc++)
            {
                KeInitializeThreadedDpc(tmp_pkdc, WriteMsrRoutine, NULL);
            }
#pragma warning(pop)
        }

        tmp_pkdc = pkdpc + (MAXIMUM_PROC_PER_GROUP * (UINT64)current_group);
        for (i = 0; i < maximumProcessor; i++, tmp_pkdc++)
        {
            PROCESSOR_MSR_FLAG[i + MAXIMUM_PROC_PER_GROUP * current_group] = RET_NOT_EXECUTED;
            group_and_processor.Number = i;
            KeSetTargetProcessorDpcEx(tmp_pkdc, &group_and_processor);
            // KeInsertQueueDpc returns FALSE when the DPC is already queued;
            // it will still fire on its own. Leave the flag as RET_NOT_EXECUTED
            // so the wait loop below waits for WriteMsrRoutine to set it.
            if (!KeInsertQueueDpc(tmp_pkdc, (PVOID)(ULONG_PTR)UsePLEOptIn, NULL))
            {
                TraceEvents(TRACE_LEVEL_WARNING, TRACE_POWER,
                    "KeInsertQueueDpc already queued for group %u proc %u; DPC will fire on its own",
                    current_group, i);
            }
        }
        // Wait for all processors in the group to finish executing the DPC
        while (1)
        {
            count = 0;
            for (i = 0; i < maximumProcessor; i++)
            {
                if (PROCESSOR_MSR_FLAG[i + MAXIMUM_PROC_PER_GROUP * current_group] != RET_NOT_EXECUTED)
                {
                    count++;
                }
                else
                {
                    break;
                }
            }
            if (count == maximumProcessor)
            {
                break;
            }
            // Yield the logical processor briefly to avoid burning CPU while
            // waiting for the DPCs to complete on other processors.
            YieldProcessor();
        }

        // Check if any of the DPCs failed to write the MSR
        for (i = 0; i < maximumProcessor; i++)
        {
            ULONG flag = PROCESSOR_MSR_FLAG[i + MAXIMUM_PROC_PER_GROUP * current_group];
            if (flag == RET_EXCEPTION)
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "Write MSRs on processor group %u processor %u threw an exception", current_group, i);
                result = FALSE;
                goto flush_and_return;
            }
            if (flag == RET_NO_FEATURE)
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "Write MSRs on processor group %u processor %u: FLC not enabled in IA32_FEATURE_CONTROL", current_group, i);
                result = FALSE;
                goto flush_and_return;
            }
        }

        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "Write MSRs finished on processor group %u", current_group);
    }

flush_and_return:
    // Wait for every WriteMsrRoutine callback to fully return before this
    // function returns. The spin loop above guarantees each DPC has written
    // its completion flag, but the callback may still be executing briefly
    // after that store. Without this flush, a subsequent FLCWriteMSRs call
    // (e.g. triggered by a registry-change notification) could attempt to
    // reuse the same KDPC objects while they are still executing:
    // KeInsertQueueDpc would return FALSE and the MSR write would silently
    // run with the previous UsePLEOptIn value. Flushing here also makes it
    // safe for D0Exit to free the DPC and flag arrays immediately after this
    // call returns.
    KeFlushQueuedDpcs();
    return result;
}

void watch_registry(HANDLE regh) {
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Entry");

    status = ZwNotifyChangeKey(regh, NULL, NULL, (PVOID)DelayedWorkQueue, &iosb, REG_NOTIFY_CHANGE_LAST_SET, TRUE, NULL, 0, FALSE);
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! ZwNotifyChangeKey failed %!STATUS!", status);
        return;
    }

    // Call FLCWriteMSRs *before* acquiring gLaunchSupportInfoLock:
    // KeFlushQueuedDpcs (called inside) requires IRQL == PASSIVE_LEVEL,
    // which would be violated while holding the spinlock.
    BOOLEAN optIn = is_PLE_OPT_IN();
    ret = FLCWriteMSRs(optIn ? TRUE : FALSE);

    // Update launch_support_info atomically under the spinlock so the
    // IOCTL reader never observes a torn struct.
    // Always clear SGX_LCP_PLATFORM_SUPPORT and the pubkey hash first so
    // a failed FLCWriteMSRs never leaves stale values from a prior call.
    KeAcquireSpinLock(&gLaunchSupportInfoLock, &oldIrql);
    if (optIn)
    {
        launch_support_info.configurationFlags |= SGX_PLE_REGISTRY_OPT_IN;
        launch_support_info.configurationFlags &= ~SGX_LCP_PLATFORM_SUPPORT;
        RtlZeroMemory(&launch_support_info.pubKeyHash, sizeof(launch_support_info.pubKeyHash));
        if (ret == TRUE)
        {
            launch_support_info.configurationFlags |= SGX_LCP_PLATFORM_SUPPORT;
            launch_support_info.pubKeyHash.pubKeyHash_Value_0 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_0;
            launch_support_info.pubKeyHash.pubKeyHash_Value_1 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_1;
            launch_support_info.pubKeyHash.pubKeyHash_Value_2 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_2;
            launch_support_info.pubKeyHash.pubKeyHash_Value_3 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_3;
        }
    }
    else
    {
        launch_support_info.configurationFlags &= ~SGX_PLE_REGISTRY_OPT_IN;
        launch_support_info.configurationFlags &= ~SGX_LCP_PLATFORM_SUPPORT;
        RtlZeroMemory(&launch_support_info.pubKeyHash, sizeof(launch_support_info.pubKeyHash));
        if (ret == TRUE)
        {
            launch_support_info.pubKeyHash.pubKeyHash_Value_0 = legacypubKeyHash.pubKeyHash_Value_0;
            launch_support_info.pubKeyHash.pubKeyHash_Value_1 = legacypubKeyHash.pubKeyHash_Value_1;
            launch_support_info.pubKeyHash.pubKeyHash_Value_2 = legacypubKeyHash.pubKeyHash_Value_2;
            launch_support_info.pubKeyHash.pubKeyHash_Value_3 = legacypubKeyHash.pubKeyHash_Value_3;
        }
    }
    KeReleaseSpinLock(&gLaunchSupportInfoLock, oldIrql);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! exit");
    return;
}



void FLCMSRNotifyRegistryChangeRoutine(PVOID StartContext)
{
    NTSTATUS status;
    WDFKEY key;
    UNREFERENCED_PARAMETER(StartContext);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Entry");

    status = WdfDriverOpenParametersRegistryKey(WdfGetDriver(), KEY_ALL_ACCESS, WDF_NO_OBJECT_ATTRIBUTES, &key);
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_POWER, "%!FUNC! WdfDriverOpenParametersRegistryKey failed %!STATUS!", status);
        PsTerminateSystemThread(status);
        return;
    }

    //Publish the WDFKEY and its framework-owned WDM handle so D0Exit can
    //tear them down via WdfRegistryClose (which also cancels the synchronous
    //ZwNotifyChangeKey wait in watch_registry).
    gRegKey = key;
    gRegKeyHandle = WdfRegistryWdmGetHandle(key);

    while (gFLCNotifyRegistryChangeThreadStatus == TRUE)
    {
        watch_registry(gRegKeyHandle);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! exit");
    PsTerminateSystemThread(STATUS_SUCCESS);
    return;
}

static BOOLEAN FLCMSRNotifyRegistryChange()
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE thread_handle;
    gFLCNotifyRegistryChangeThreadStatus = TRUE;

    status = PsCreateSystemThread(&thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        FLCMSRNotifyRegistryChangeRoutine,
        NULL);

    if (!NT_SUCCESS(status))
    {
        gFLCNotifyRegistryChangeThreadStatus = FALSE;
        return FALSE;
    }

    status = ObReferenceObjectByHandle(
        thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        &gFLCNotifyRegistryChangeThreadObject,
        NULL);

    if (!NT_SUCCESS(status))
    {
        gFLCNotifyRegistryChangeThreadStatus = FALSE;
        //Release the thread handle on the error path; the worker thread will
        //still terminate on its own once it observes the cleared status flag.
        ZwClose(thread_handle);
        return FALSE;
    }

    ZwClose(thread_handle);
    return TRUE;
}


NTSTATUS
FLCMSREvtDeviceD0Entry(
    IN WDFDEVICE                Device,
    IN WDF_POWER_DEVICE_STATE   RecentPowerState
)
{
    BOOLEAN ret = 0;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(RecentPowerState);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Entry");

    // Initialize before the registry thread starts or any IOCTL can arrive.
    KeInitializeSpinLock(&gLaunchSupportInfoLock);

    if (is_OS_support_FLC())
        launch_support_info.configurationFlags = SGX_LCP_OS_PERMISSION;
    else
        return STATUS_SUCCESS;

    //clear the platform support bit, set the bit if and only if successfuly update MSR
    launch_support_info.configurationFlags &= ~SGX_LCP_PLATFORM_SUPPORT;

    if (is_HW_support_FLC())
    {
        ReadMsr();
    }

    if (is_PLE_OPT_IN())
    {
        launch_support_info.configurationFlags |= SGX_PLE_REGISTRY_OPT_IN;

        if (is_HW_support_FLC())
        {
            ret = FLCWriteMSRs(TRUE);

            if (ret == TRUE)
            {
                launch_support_info.configurationFlags |= SGX_LCP_PLATFORM_SUPPORT;
                launch_support_info.pubKeyHash.pubKeyHash_Value_0 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_0;
                launch_support_info.pubKeyHash.pubKeyHash_Value_1 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_1;
                launch_support_info.pubKeyHash.pubKeyHash_Value_2 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_2;
                launch_support_info.pubKeyHash.pubKeyHash_Value_3 = MSR_IA32_SGX_LE_PUBKEYHASH_VALUE_3;
            }
        }
    }
    
    if (is_HW_support_FLC())
    {
        FLCMSRNotifyRegistryChange();
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "%!FUNC! Exit %x", launch_support_info.configurationFlags);

    //always return success because we need to support IOCTL_SGX_GETLAUNCHSUPPORT
    return STATUS_SUCCESS;
}

NTSTATUS
FLCMSREvtDeviceD0Exit(
    IN WDFDEVICE                Device,
    IN WDF_POWER_DEVICE_STATE   PowerState
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PowerState);

    if (gFLCNotifyRegistryChangeThreadStatus == TRUE)
    {
        gFLCNotifyRegistryChangeThreadStatus = FALSE;
        //The WDM handle returned by WdfRegistryWdmGetHandle is owned by the
        //framework; closing it with ZwClose would be a CWE-672 lifecycle
        //violation. Closing the parent WDFKEY releases the underlying handle
        //and cancels the pending synchronous ZwNotifyChangeKey wait, letting
        //the worker thread observe the cleared status flag and exit.
        if (gRegKey != NULL)
        {
            WdfRegistryClose(gRegKey);
            gRegKey = NULL;
            gRegKeyHandle = NULL;
        }

        KeWaitForSingleObject(
            gFLCNotifyRegistryChangeThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(gFLCNotifyRegistryChangeThreadObject);
    }

    if (is_HW_support_FLC())
    {
        FLCWriteMSRs(FALSE);
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_POWER, "Write legacy LE mrsigner when exit");
    }

    if (PROCESSOR_MSR_FLAG)
    {
        ExFreePoolWithTag((PVOID)(ULONG_PTR)PROCESSOR_MSR_FLAG, 'flag');
        PROCESSOR_MSR_FLAG = NULL;
    }
    if (pkdpc)
    {
        ExFreePoolWithTag(pkdpc, 'kdpc');
        pkdpc = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
FLCMSREvtDevicePrepareHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourceList,
    _In_ WDFCMRESLIST ResourceListTranslated
)
/*++

Routine Description:

In this callback, the driver does whatever is necessary to make the
hardware ready to use.  In the case of a USB device, this involves
reading and selecting descriptors.

Arguments:

Device - handle to a device

Return Value:

NT status value

--*/
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(ResourceList);
    UNREFERENCED_PARAMETER(ResourceListTranslated);

    return STATUS_SUCCESS;
}