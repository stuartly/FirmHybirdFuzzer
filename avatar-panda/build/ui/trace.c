/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "trace.h"

uint16_t _TRACE_CONSOLE_GFX_NEW_DSTATE;
uint16_t _TRACE_CONSOLE_PUTCHAR_CSI_DSTATE;
uint16_t _TRACE_CONSOLE_PUTCHAR_UNHANDLED_DSTATE;
uint16_t _TRACE_CONSOLE_TXT_NEW_DSTATE;
uint16_t _TRACE_CONSOLE_SELECT_DSTATE;
uint16_t _TRACE_CONSOLE_REFRESH_DSTATE;
uint16_t _TRACE_DISPLAYSURFACE_CREATE_DSTATE;
uint16_t _TRACE_DISPLAYSURFACE_CREATE_FROM_DSTATE;
uint16_t _TRACE_DISPLAYSURFACE_CREATE_PIXMAN_DSTATE;
uint16_t _TRACE_DISPLAYSURFACE_FREE_DSTATE;
uint16_t _TRACE_DISPLAYCHANGELISTENER_REGISTER_DSTATE;
uint16_t _TRACE_DISPLAYCHANGELISTENER_UNREGISTER_DSTATE;
uint16_t _TRACE_PPM_SAVE_DSTATE;
uint16_t _TRACE_GD_SWITCH_DSTATE;
uint16_t _TRACE_GD_UPDATE_DSTATE;
uint16_t _TRACE_GD_KEY_EVENT_DSTATE;
uint16_t _TRACE_GD_GRAB_DSTATE;
uint16_t _TRACE_GD_UNGRAB_DSTATE;
uint16_t _TRACE_VNC_KEY_GUEST_LEDS_DSTATE;
uint16_t _TRACE_VNC_KEY_MAP_INIT_DSTATE;
uint16_t _TRACE_VNC_KEY_EVENT_EXT_DSTATE;
uint16_t _TRACE_VNC_KEY_EVENT_MAP_DSTATE;
uint16_t _TRACE_VNC_KEY_SYNC_NUMLOCK_DSTATE;
uint16_t _TRACE_VNC_KEY_SYNC_CAPSLOCK_DSTATE;
uint16_t _TRACE_INPUT_EVENT_KEY_NUMBER_DSTATE;
uint16_t _TRACE_INPUT_EVENT_KEY_QCODE_DSTATE;
uint16_t _TRACE_INPUT_EVENT_BTN_DSTATE;
uint16_t _TRACE_INPUT_EVENT_REL_DSTATE;
uint16_t _TRACE_INPUT_EVENT_ABS_DSTATE;
uint16_t _TRACE_INPUT_EVENT_SYNC_DSTATE;
uint16_t _TRACE_INPUT_MOUSE_MODE_DSTATE;
uint16_t _TRACE_QEMU_SPICE_ADD_MEMSLOT_DSTATE;
uint16_t _TRACE_QEMU_SPICE_DEL_MEMSLOT_DSTATE;
uint16_t _TRACE_QEMU_SPICE_CREATE_PRIMARY_SURFACE_DSTATE;
uint16_t _TRACE_QEMU_SPICE_DESTROY_PRIMARY_SURFACE_DSTATE;
uint16_t _TRACE_QEMU_SPICE_WAKEUP_DSTATE;
uint16_t _TRACE_QEMU_SPICE_CREATE_UPDATE_DSTATE;
TraceEvent _TRACE_CONSOLE_GFX_NEW_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_gfx_new",
    .sstate = TRACE_CONSOLE_GFX_NEW_ENABLED,
    .dstate = &_TRACE_CONSOLE_GFX_NEW_DSTATE 
};
TraceEvent _TRACE_CONSOLE_PUTCHAR_CSI_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_putchar_csi",
    .sstate = TRACE_CONSOLE_PUTCHAR_CSI_ENABLED,
    .dstate = &_TRACE_CONSOLE_PUTCHAR_CSI_DSTATE 
};
TraceEvent _TRACE_CONSOLE_PUTCHAR_UNHANDLED_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_putchar_unhandled",
    .sstate = TRACE_CONSOLE_PUTCHAR_UNHANDLED_ENABLED,
    .dstate = &_TRACE_CONSOLE_PUTCHAR_UNHANDLED_DSTATE 
};
TraceEvent _TRACE_CONSOLE_TXT_NEW_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_txt_new",
    .sstate = TRACE_CONSOLE_TXT_NEW_ENABLED,
    .dstate = &_TRACE_CONSOLE_TXT_NEW_DSTATE 
};
TraceEvent _TRACE_CONSOLE_SELECT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_select",
    .sstate = TRACE_CONSOLE_SELECT_ENABLED,
    .dstate = &_TRACE_CONSOLE_SELECT_DSTATE 
};
TraceEvent _TRACE_CONSOLE_REFRESH_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "console_refresh",
    .sstate = TRACE_CONSOLE_REFRESH_ENABLED,
    .dstate = &_TRACE_CONSOLE_REFRESH_DSTATE 
};
TraceEvent _TRACE_DISPLAYSURFACE_CREATE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaysurface_create",
    .sstate = TRACE_DISPLAYSURFACE_CREATE_ENABLED,
    .dstate = &_TRACE_DISPLAYSURFACE_CREATE_DSTATE 
};
TraceEvent _TRACE_DISPLAYSURFACE_CREATE_FROM_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaysurface_create_from",
    .sstate = TRACE_DISPLAYSURFACE_CREATE_FROM_ENABLED,
    .dstate = &_TRACE_DISPLAYSURFACE_CREATE_FROM_DSTATE 
};
TraceEvent _TRACE_DISPLAYSURFACE_CREATE_PIXMAN_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaysurface_create_pixman",
    .sstate = TRACE_DISPLAYSURFACE_CREATE_PIXMAN_ENABLED,
    .dstate = &_TRACE_DISPLAYSURFACE_CREATE_PIXMAN_DSTATE 
};
TraceEvent _TRACE_DISPLAYSURFACE_FREE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaysurface_free",
    .sstate = TRACE_DISPLAYSURFACE_FREE_ENABLED,
    .dstate = &_TRACE_DISPLAYSURFACE_FREE_DSTATE 
};
TraceEvent _TRACE_DISPLAYCHANGELISTENER_REGISTER_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaychangelistener_register",
    .sstate = TRACE_DISPLAYCHANGELISTENER_REGISTER_ENABLED,
    .dstate = &_TRACE_DISPLAYCHANGELISTENER_REGISTER_DSTATE 
};
TraceEvent _TRACE_DISPLAYCHANGELISTENER_UNREGISTER_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "displaychangelistener_unregister",
    .sstate = TRACE_DISPLAYCHANGELISTENER_UNREGISTER_ENABLED,
    .dstate = &_TRACE_DISPLAYCHANGELISTENER_UNREGISTER_DSTATE 
};
TraceEvent _TRACE_PPM_SAVE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "ppm_save",
    .sstate = TRACE_PPM_SAVE_ENABLED,
    .dstate = &_TRACE_PPM_SAVE_DSTATE 
};
TraceEvent _TRACE_GD_SWITCH_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "gd_switch",
    .sstate = TRACE_GD_SWITCH_ENABLED,
    .dstate = &_TRACE_GD_SWITCH_DSTATE 
};
TraceEvent _TRACE_GD_UPDATE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "gd_update",
    .sstate = TRACE_GD_UPDATE_ENABLED,
    .dstate = &_TRACE_GD_UPDATE_DSTATE 
};
TraceEvent _TRACE_GD_KEY_EVENT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "gd_key_event",
    .sstate = TRACE_GD_KEY_EVENT_ENABLED,
    .dstate = &_TRACE_GD_KEY_EVENT_DSTATE 
};
TraceEvent _TRACE_GD_GRAB_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "gd_grab",
    .sstate = TRACE_GD_GRAB_ENABLED,
    .dstate = &_TRACE_GD_GRAB_DSTATE 
};
TraceEvent _TRACE_GD_UNGRAB_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "gd_ungrab",
    .sstate = TRACE_GD_UNGRAB_ENABLED,
    .dstate = &_TRACE_GD_UNGRAB_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_GUEST_LEDS_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_guest_leds",
    .sstate = TRACE_VNC_KEY_GUEST_LEDS_ENABLED,
    .dstate = &_TRACE_VNC_KEY_GUEST_LEDS_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_MAP_INIT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_map_init",
    .sstate = TRACE_VNC_KEY_MAP_INIT_ENABLED,
    .dstate = &_TRACE_VNC_KEY_MAP_INIT_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_EVENT_EXT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_event_ext",
    .sstate = TRACE_VNC_KEY_EVENT_EXT_ENABLED,
    .dstate = &_TRACE_VNC_KEY_EVENT_EXT_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_EVENT_MAP_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_event_map",
    .sstate = TRACE_VNC_KEY_EVENT_MAP_ENABLED,
    .dstate = &_TRACE_VNC_KEY_EVENT_MAP_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_SYNC_NUMLOCK_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_sync_numlock",
    .sstate = TRACE_VNC_KEY_SYNC_NUMLOCK_ENABLED,
    .dstate = &_TRACE_VNC_KEY_SYNC_NUMLOCK_DSTATE 
};
TraceEvent _TRACE_VNC_KEY_SYNC_CAPSLOCK_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "vnc_key_sync_capslock",
    .sstate = TRACE_VNC_KEY_SYNC_CAPSLOCK_ENABLED,
    .dstate = &_TRACE_VNC_KEY_SYNC_CAPSLOCK_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_KEY_NUMBER_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_key_number",
    .sstate = TRACE_INPUT_EVENT_KEY_NUMBER_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_KEY_NUMBER_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_KEY_QCODE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_key_qcode",
    .sstate = TRACE_INPUT_EVENT_KEY_QCODE_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_KEY_QCODE_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_BTN_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_btn",
    .sstate = TRACE_INPUT_EVENT_BTN_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_BTN_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_REL_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_rel",
    .sstate = TRACE_INPUT_EVENT_REL_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_REL_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_ABS_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_abs",
    .sstate = TRACE_INPUT_EVENT_ABS_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_ABS_DSTATE 
};
TraceEvent _TRACE_INPUT_EVENT_SYNC_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_event_sync",
    .sstate = TRACE_INPUT_EVENT_SYNC_ENABLED,
    .dstate = &_TRACE_INPUT_EVENT_SYNC_DSTATE 
};
TraceEvent _TRACE_INPUT_MOUSE_MODE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "input_mouse_mode",
    .sstate = TRACE_INPUT_MOUSE_MODE_ENABLED,
    .dstate = &_TRACE_INPUT_MOUSE_MODE_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_ADD_MEMSLOT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_add_memslot",
    .sstate = TRACE_QEMU_SPICE_ADD_MEMSLOT_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_ADD_MEMSLOT_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_DEL_MEMSLOT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_del_memslot",
    .sstate = TRACE_QEMU_SPICE_DEL_MEMSLOT_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_DEL_MEMSLOT_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_CREATE_PRIMARY_SURFACE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_create_primary_surface",
    .sstate = TRACE_QEMU_SPICE_CREATE_PRIMARY_SURFACE_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_CREATE_PRIMARY_SURFACE_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_DESTROY_PRIMARY_SURFACE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_destroy_primary_surface",
    .sstate = TRACE_QEMU_SPICE_DESTROY_PRIMARY_SURFACE_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_DESTROY_PRIMARY_SURFACE_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_WAKEUP_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_wakeup",
    .sstate = TRACE_QEMU_SPICE_WAKEUP_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_WAKEUP_DSTATE 
};
TraceEvent _TRACE_QEMU_SPICE_CREATE_UPDATE_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "qemu_spice_create_update",
    .sstate = TRACE_QEMU_SPICE_CREATE_UPDATE_ENABLED,
    .dstate = &_TRACE_QEMU_SPICE_CREATE_UPDATE_DSTATE 
};
TraceEvent *ui_trace_events[] = {
    &_TRACE_CONSOLE_GFX_NEW_EVENT,
    &_TRACE_CONSOLE_PUTCHAR_CSI_EVENT,
    &_TRACE_CONSOLE_PUTCHAR_UNHANDLED_EVENT,
    &_TRACE_CONSOLE_TXT_NEW_EVENT,
    &_TRACE_CONSOLE_SELECT_EVENT,
    &_TRACE_CONSOLE_REFRESH_EVENT,
    &_TRACE_DISPLAYSURFACE_CREATE_EVENT,
    &_TRACE_DISPLAYSURFACE_CREATE_FROM_EVENT,
    &_TRACE_DISPLAYSURFACE_CREATE_PIXMAN_EVENT,
    &_TRACE_DISPLAYSURFACE_FREE_EVENT,
    &_TRACE_DISPLAYCHANGELISTENER_REGISTER_EVENT,
    &_TRACE_DISPLAYCHANGELISTENER_UNREGISTER_EVENT,
    &_TRACE_PPM_SAVE_EVENT,
    &_TRACE_GD_SWITCH_EVENT,
    &_TRACE_GD_UPDATE_EVENT,
    &_TRACE_GD_KEY_EVENT_EVENT,
    &_TRACE_GD_GRAB_EVENT,
    &_TRACE_GD_UNGRAB_EVENT,
    &_TRACE_VNC_KEY_GUEST_LEDS_EVENT,
    &_TRACE_VNC_KEY_MAP_INIT_EVENT,
    &_TRACE_VNC_KEY_EVENT_EXT_EVENT,
    &_TRACE_VNC_KEY_EVENT_MAP_EVENT,
    &_TRACE_VNC_KEY_SYNC_NUMLOCK_EVENT,
    &_TRACE_VNC_KEY_SYNC_CAPSLOCK_EVENT,
    &_TRACE_INPUT_EVENT_KEY_NUMBER_EVENT,
    &_TRACE_INPUT_EVENT_KEY_QCODE_EVENT,
    &_TRACE_INPUT_EVENT_BTN_EVENT,
    &_TRACE_INPUT_EVENT_REL_EVENT,
    &_TRACE_INPUT_EVENT_ABS_EVENT,
    &_TRACE_INPUT_EVENT_SYNC_EVENT,
    &_TRACE_INPUT_MOUSE_MODE_EVENT,
    &_TRACE_QEMU_SPICE_ADD_MEMSLOT_EVENT,
    &_TRACE_QEMU_SPICE_DEL_MEMSLOT_EVENT,
    &_TRACE_QEMU_SPICE_CREATE_PRIMARY_SURFACE_EVENT,
    &_TRACE_QEMU_SPICE_DESTROY_PRIMARY_SURFACE_EVENT,
    &_TRACE_QEMU_SPICE_WAKEUP_EVENT,
    &_TRACE_QEMU_SPICE_CREATE_UPDATE_EVENT,
  NULL,
};

static void trace_ui_register_events(void)
{
    trace_event_register_group(ui_trace_events);
}
trace_init(trace_ui_register_events)
