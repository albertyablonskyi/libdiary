#ifndef LIBDIARY_LOG_H
#define LIBDIARY_LOG_H

#include <stdlib.h>
#include <stdarg.h>

#define SHOW_OUTPUT TRUE
#define SHOW_DEBUG TRUE

typedef enum {
    SUCCESS,
    WARNING,
    ERROR,
    DEBUG
} MessageType;


void log_message(MessageType type, const char* message, ...);

#endif // LIBDIARY_LOG_H
