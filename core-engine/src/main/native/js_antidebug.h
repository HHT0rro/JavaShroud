#ifndef JS_ANTIDEBUG_H
#define JS_ANTIDEBUG_H

#include "js_native_common.h"

JS_HIDDEN void js_native_anti_dump_harden(void);
JS_HIDDEN int js_vm_strong_debugger_present(void);

#endif
