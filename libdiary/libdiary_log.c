#include "libdiary.h"
#include "libdiary_log.h"

// Print formatted message
void log_message(MessageType type, const char* message, ...) {
    // Check SHOW_OUPUT option
    if (!SHOW_OUTPUT) {
        return;
    }

    const char* prefix = NULL;

    switch (type) {
        case SUCCESS:
            prefix = "[libdiary v%s] SUCCESS: ";
            break;
        case WARNING:
            prefix = "[libdiary v%s] WARNING: ";
            break;
        case ERROR:
            prefix = "[libdiary v%s] ERROR: ";
            break;
        case DEBUG:
            if (SHOW_DEBUG) {
            prefix = "[libdiary v%s] DEBUG: ";
            break;
            }
            else {
                return;
            }

        default:
            prefix = "[libdiary v%s] GENIE SAYS: ";
    }

    va_list args;
    va_start(args, message);

    printf(prefix, LIBDIARY_VERSION);
    vprintf(message, args);
    printf("\n");

    va_end(args);
}