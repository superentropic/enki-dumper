#pragma once
#include <cmath>
#include <fstream>
#include "Json/json.hpp"
#include "Unreal/ObjectArray.h"
#include "TargetMemory.h"

inline nlohmann::ordered_json ValidateLinuxReflection()
{
    using Json = nlohmann::ordered_json;
    Json report;
    report["upstream_commit"] = "dd8fe34df8283378a1055386eee195005a100924";
    report["pid"] = PlatformLinux::GetProcessId();
    report["object_count"] = ObjectArray::Num();
    report["item_size"] = Off::InSDK::ObjArray::FUObjectItemSize;
    report["item_pointer_offset"] = Off::InSDK::ObjArray::FUObjectItemInitialOffset;
    int checked = 0;
    for (int i = 0; i < ObjectArray::Num() && checked < 2048; ++i) {
        auto object = ObjectArray::GetByIndex(i);
        if (!object) continue;
        if (object.GetIndex() != i || object.GetName().empty() || !object.GetClass())
            throw std::runtime_error("Object index/name/class validation failed at " + std::to_string(i));
        ++checked;
    }
    if (checked < 2048) throw std::runtime_error("Insufficient readable objects for SDK validation");
    report["checked_object_indices"] = checked;
    struct Required { const char* owner; const char* member; };
    const Required required[] = {
        {"World", "OwningGameInstance"}, {"GameInstance", "LocalPlayers"},
        {"Player", "PlayerController"}, {"PlayerController", "PlayerCameraManager"},
        {"PlayerCameraManager", "CameraCachePrivate"}, {"CameraCacheEntry", "POV"},
        {"MinimalViewInfo", "Location"}, {"MinimalViewInfo", "Rotation"}, {"MinimalViewInfo", "FOV"},
        {"Vector", "X"}, {"Guid", "A"}, {"Guid", "D"}
    };
    for (const auto& check : required) {
        const auto owner = ObjectArray::FindStructFast(check.owner);
        const auto member = owner.FindMember(check.member);
        if (!owner || !member || member.GetOffset() < 0 || member.GetSize() <= 0 ||
            int64(member.GetOffset()) + member.GetSize() > owner.GetStructSize())
            throw std::runtime_error(std::string("Reflected bounds validation failed: ") + check.owner + "::" + check.member);
        report["properties"][std::string(check.owner) + "::" + check.member] = {
            {"owner_cpp", owner.GetCppName()}, {"offset", member.GetOffset()},
            {"size", member.GetSize()}, {"owner_size", owner.GetStructSize()},
            {"type", member.GetCppType()}, {"property_address", reinterpret_cast<uintptr_t>(member.GetAddress())}
        };
    }
    const auto offset = [&](const char* key) { return report["properties"][key]["offset"].get<uintptr_t>(); };
    report["globals"] = {{"GObjects", Off::InSDK::ObjArray::GObjects}, {"GNames", Off::InSDK::NameArray::GNames},
                         {"GWorld", Off::InSDK::World::GWorld}, {"ProcessEvent", Off::InSDK::ProcessEvent::PEOffset},
                         {"ProcessEventIndex", Off::InSDK::ProcessEvent::PEIndex}};
    // Cross-check the reflected offsets with fresh reads of the live chain.
    const auto readPointer = [](uintptr_t address) { return PlatformLinux::ReadOr<uintptr_t>(address); };
    const auto world = readPointer(PlatformLinux::GetModuleBase() + Off::InSDK::World::GWorld);
    const auto instance = world ? readPointer(world + offset("World::OwningGameInstance")) : 0;
    const auto players = instance ? readPointer(instance + offset("GameInstance::LocalPlayers")) : 0;
    const auto local = players ? readPointer(players) : 0;
    const auto controller = local ? readPointer(local + offset("Player::PlayerController")) : 0;
    const auto camera = controller ? readPointer(controller + offset("PlayerController::PlayerCameraManager")) : 0;
    report["live_chain"] = {{"world", world}, {"game_instance", instance}, {"local_player", local},
                             {"player_controller", controller}, {"camera_manager", camera}};
    if (world && instance && local && controller && camera) {
        const auto pov = camera + offset("PlayerCameraManager::CameraCachePrivate") + offset("CameraCacheEntry::POV");
        float fov{};
        const bool valid = PlatformLinux::Read(pov + offset("MinimalViewInfo::FOV"), fov) && std::isfinite(fov) && fov > 0 && fov < 180;
        report["live_chain"]["fov"] = fov;
        report["live_chain"]["camera_values_readable"] = valid;
    } else report["live_chain"]["camera_values_readable"] = false;
    report["reflection_validation"] = "passed";
    return report;
}
