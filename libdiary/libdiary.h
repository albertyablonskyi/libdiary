
#ifndef LIBDIARY_H
#define LIBDIARY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <libgen.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <sodium.h>

#define LIBDIARY_VERSION "0.0.1"
#define CHUNK_SIZE 4096
#define MAX_DATE_LENGTH 11  // "yyyy-mm-dd\0"

#endif // LIBDIARY_H