#define WIN32_LEAN_AND_MEAN

#include "Windows.h"
#include "memoryapi.h"
#include "memory.h"

#include "scssdk_telemetry.h"

uintptr_t g_attribute_type_check_address = NULL;
uintptr_t game_base;

scs_log_t scs_log = nullptr;

DWORD old_acc_protect = NULL;

void cleanup()
{
    if (g_attribute_type_check_address == 0)
    {
        return;
    }

    VirtualProtect(reinterpret_cast<LPVOID>(g_attribute_type_check_address),
                   2,
                   PAGE_EXECUTE_READWRITE,
                   &old_acc_protect);
    const auto jmp = reinterpret_cast<uint16_t*>(g_attribute_type_check_address);
    *jmp = 0x840F;
    VirtualProtect(reinterpret_cast<LPVOID>(g_attribute_type_check_address), 2, old_acc_protect, nullptr);
    scs_log(SCS_LOG_TYPE_message, "[ScsUnitTypeCheckBypass] Unpatched Attribute Type Check");
}

bool bypass_type_check()
{
    if (g_attribute_type_check_address == 0)
    {
        return false;
    }

    VirtualProtect(reinterpret_cast<LPVOID>(g_attribute_type_check_address),
                   2,
                   PAGE_EXECUTE_READWRITE,
                   &old_acc_protect);
    const auto je = reinterpret_cast<uint16_t*>(g_attribute_type_check_address);
    *je = 0xE990;
    VirtualProtect(reinterpret_cast<LPVOID>(g_attribute_type_check_address), 2, old_acc_protect, nullptr);
    scs_log(SCS_LOG_TYPE_message, "[ScsUnitTypeCheckBypass] Patched Attribute Type Check");
    return true;
}

SCSAPI_RESULT scs_telemetry_init(const scs_u32_t version, const scs_telemetry_init_params_t* const params)
{
    // We currently support only one version.
    if (version != SCS_TELEMETRY_VERSION_1_01)
    {
        return SCS_RESULT_unsupported;
    }

    const auto version_params = reinterpret_cast<const scs_telemetry_init_params_v101_t*>(params);
    scs_log = version_params->common.log;

    std::stringstream ss;
    ss << "[ScsUnitTypeCheckBypass] Found type check jump address @ &" << std::hex <<
        g_attribute_type_check_address << " "
        << (strcmp(version_params->common.game_id, "eut2") == 0 ? "eurotrucks2" : "amtrucks") << ".exe+"
        << (g_attribute_type_check_address - game_base);
    scs_log(SCS_LOG_TYPE_message, ss.str().c_str());

    if (!bypass_type_check())
    {
        version_params->common.log(SCS_LOG_TYPE_error,
                                   "[ScsUnitTypeCheckBypass] Could not bypass attribute type check");
        return SCS_RESULT_invalid_parameter;
    }

    scs_log(SCS_LOG_TYPE_message, "[ScsUnitTypeCheckBypass] Plugin Loaded");

    return SCS_RESULT_ok;
}


/**
 * @brief Telemetry API deinitialization function.
 *
 * See scssdk_telemetry.h
 */
SCSAPI_VOID scs_telemetry_shutdown(void)
{
    cleanup();
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        game_base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
        const auto header = reinterpret_cast<const IMAGE_DOS_HEADER*>(game_base);
        const auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const uint8_t*>(header) + header->e_lfanew);
        const auto total_size = nt_header->OptionalHeader.SizeOfImage;

        g_attribute_type_check_address = pattern::scan("0F 84 ? ? ? ? 8B 53 0C 48 8D 4D E8 4C 89 65 F8",
                                                       game_base,
                                                       total_size);
    }

    return TRUE;
}
