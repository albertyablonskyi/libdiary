/*
*   Copyright (C) 2024 Albert Yablonskyi
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "libdiary.h"
#include "libdiary_log.h"

/*
    Functions to delete folder along with contents, used in cleanup()
    Shamelessly taken from nautilus-file-operations.c (https://gitlab.gnome.org/GNOME/nautilus)
    ===
*/
typedef void (*DeleteCallback) (GFile   *file,
                                GError  *error,
                                gpointer callback_data);

static void delete_callback(GFile *file, GError *error, gpointer data)
{
    if (error != NULL)
    {
        log_message(ERROR, "Deletion failed for file %s: %s", g_file_get_path(file), error->message);
    }
    else
    {
        log_message(SUCCESS, "Successfully deleted file: %s", g_file_get_path(file));
    }
}

static gboolean
delete_file_recursively (GFile          *file,
                         GCancellable   *cancellable,
                         DeleteCallback  callback,
                         gpointer        callback_data)
{
    gboolean success;
    g_autoptr (GError) error = NULL;

    do
    {
        g_autoptr (GFileEnumerator) enumerator = NULL;

        success = g_file_delete (file, cancellable, &error);
        if (success ||
            !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_EMPTY))
        {
            break;
        }

        g_clear_error (&error);

        enumerator = g_file_enumerate_children (file,
                                                G_FILE_ATTRIBUTE_STANDARD_NAME,
                                                G_FILE_QUERY_INFO_NONE,
                                                cancellable, &error);

        if (enumerator)
        {
            GFileInfo *info;

            success = TRUE;

            info = g_file_enumerator_next_file (enumerator,
                                                cancellable,
                                                &error);

            while (info != NULL)
            {
                g_autoptr (GFile) child = NULL;

                child = g_file_enumerator_get_child (enumerator, info);

                success = success && delete_file_recursively (child,
                                                              cancellable,
                                                              callback,
                                                              callback_data);

                g_object_unref (info);

                info = g_file_enumerator_next_file (enumerator,
                                                    cancellable,
                                                    &error);
            }
        }

        if (error != NULL)
        {
            success = FALSE;
        }
    }
    while (success);

    if (callback)
    {
        if (!success && error == NULL)
        {
            /* Enumeration succeeded, but we've failed to delete at least one child. */
            error = g_error_new (G_IO_ERROR,
                                 G_IO_ERROR_NOT_EMPTY,
                                 _("Failed to delete all child files"));
        }

        callback (file, error, callback_data);
    }

    return success;
}
/*
    ===
*/

/*
    Build path for database in tmp folder.
*/
char* diary_path_builder() {
    char parent_folder[100];

    snprintf(parent_folder, sizeof(parent_folder), "%s/libdiary/%ld", g_get_tmp_dir(), time(NULL));

    if (g_mkdir_with_parents(parent_folder, 0700)) {
        g_critical("Failed to create tmp diary folder!");
        return NULL;
    }

    char *path = g_strdup_printf("%s/db", parent_folder);

    return path;
}

/*
    Build uri path for file in tmp folder.
*/
static bool file_uri_path_builder(char* path, size_t size, const char* parent_folder, const char* filename) {
    snprintf(path, size, "%s/%s", parent_folder, filename);
    
    return TRUE;
}

/*
    Cleanup function.
*/
bool cleanup(sqlite3 *db)
{
    if (db != NULL)
    {
        g_autofree gchar *folder_path = g_path_get_dirname(sqlite3_db_filename(db, "main"));

        if (sqlite3_close(db) != SQLITE_OK)
        {
            log_message(ERROR, "Failed to close database connection!");
            return FALSE;
        }

        g_autofree GFile *folder_file = g_file_new_for_path(folder_path);
        GCancellable *cancellable = g_cancellable_new();
        g_autofree gpointer callback_data = NULL;
        gboolean success = delete_file_recursively(folder_file, cancellable, delete_callback, callback_data);

        if (success)
        {
            log_message(SUCCESS, "Cleanup completed successfully.");
        }
        else
        {
            log_message(ERROR, "Cleanup failed.");
            return FALSE;
        }
    }
    return TRUE;
}

/*
    Create and return sqlite db connection.
*/
sqlite3* create_diary() {
    // Create tmp diary_path
    g_autofree char* diary_path = diary_path_builder();

    // Initialize db
    sqlite3* db;
    if (sqlite3_open(diary_path, &db) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    // Create tables
    static const char* CREATE_TABLE_NOTES =
    "CREATE TABLE IF NOT EXISTS notes("
    "    note_id INTEGER PRIMARY KEY,"
    "    title TEXT,"
    "    body TEXT,"
    "    date DATE,"
    "    created_at TIMESTAMP"
    ");";

    static const char*  CREATE_TABLE_FILES =
        "CREATE TABLE IF NOT EXISTS files("
        "    file_id INTEGER PRIMARY KEY,"
        "    note_id INTEGER,"
        "    filename TEXT,"
        "    type TEXT,"
        "    size INTEGER,"
        "    binary_data BLOB,"
        "    hash VARCHAR(64),"
        "    created_at TIMESTAMP"
        ");";

    // Create table NOTES
    if (sqlite3_exec(db, CREATE_TABLE_NOTES, 0, 0, NULL) != 0) {
        log_message(ERROR, "Table \"NOTES\" creation failed.");
        return NULL;
    }

    // Create table FILES
    if (sqlite3_exec(db, CREATE_TABLE_FILES, 0, 0, NULL) != 0) {
        log_message(ERROR, "Table \"FILES\" creation failed.");
        return NULL;
    }

    log_message(SUCCESS, "Diary created successfully!");
    return db;
}

/*
    Decrypt diary and return sqlite connection.
    Strongly based on https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream
*/
sqlite3* open_diary(const char* source_file, const char* password) {
    // Create tmp diary_path
    g_autofree char* diary_path = diary_path_builder();

    // FILEs
    FILE *fp_t, *fp_s;
    fp_s = fopen(source_file, "rb");
    fp_t = fopen(diary_path, "wb");

    // Init secretstream variables
    unsigned char buf_in [CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out [CHUNK_SIZE];
    unsigned char header [crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t rlen;
    int eof;
    unsigned char tag;

    // Init and read salt
    unsigned char salt [crypto_pwhash_SALTBYTES];
    fp_s = fopen(source_file, "rb");
    if (fp_s == NULL) {
        log_message(ERROR, "Error opening file %s", source_file);
        return NULL;
    }
    fread(salt, 1, crypto_pwhash_SALTBYTES, fp_s);

    // Init key
    unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
    if (crypto_pwhash
       (key, sizeof key, password, strlen(password), salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            log_message(ERROR, "Failed to initialize key from password.");
            return NULL;
    }

    // Init secretstream decrypt
    fread(header, 1, sizeof header, fp_s);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        log_message(ERROR, "Failed to initialize secret stream! Incomplete header.");
        return NULL;
    }

    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);

        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                        buf_in, rlen, NULL, 0) != 0) {
            log_message(ERROR, "Failed to decrypt! Corrupted chunk.");
            fclose(fp_s);
            fclose(fp_t);
            return NULL;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (!eof) {
                // Very stupid workaround, but meh
                eof = 1;
            } else {
                break;
            }
        } else { /* not the final chunk yet */
            if (eof) {
                log_message(ERROR, "Reached end of file without final tag.");
                fclose(fp_s);
                fclose(fp_t);
                return NULL;
            }
        }

        fwrite(buf_out, 1, (size_t) out_len, fp_t);

    } while (!eof);
    
    log_message(SUCCESS, "Diary decrypted");
    fclose(fp_s);
    fclose(fp_t);

    sqlite3* db;

    // Initialize db
    if (sqlite3_open(diary_path, &db) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    // Check the integrity of the database
    if (sqlite3_exec(db, "PRAGMA integrity_check;", 0, 0, 0) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    
    log_message(SUCCESS, "Diary opened successfully!");
    return db;
}

/*
    Encrypt and save diary.
*/
bool save_diary(sqlite3* db, const char *target_file, const char* password) {
    // FILEs
    FILE *fp_t, *fp_s;
    fp_s = fopen(sqlite3_db_filename(db, "main"), "rb");
    fp_t = fopen(target_file, "wb");

    if (fp_t == NULL) {
        log_message(ERROR, "Error opening diary.");
        return FALSE;
    }

    // Init and write salt
    unsigned char salt [crypto_pwhash_SALTBYTES];
    randombytes(salt, crypto_pwhash_SALTBYTES);
    fwrite(salt, 1, crypto_pwhash_SALTBYTES, fp_t);

    // Init key
    unsigned char key [crypto_aead_chacha20poly1305_KEYBYTES];
    if (crypto_pwhash
       (key, sizeof key, password, strlen(password), salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
            log_message(ERROR, "Failed to initialize key from password.");
            return FALSE;
    }

    // Init secretstream variables
    unsigned char buf_in [CHUNK_SIZE];
    unsigned char buf_out [CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header [crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t rlen = 0;
    int eof;
    unsigned char tag;

    // Init secretstream
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);

    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);

    fclose(fp_t);
    fclose(fp_s);

    log_message(SUCCESS, "Diary saved successfully!");
    return TRUE;
}

/*
    Export database from unlocked diary.
*/
bool export_database(sqlite3* db, const char *filepath) {
    // Initialize backup db
    sqlite3 *fileDB = NULL;

    if (sqlite3_open(filepath, &fileDB) != 0) {
        log_message(ERROR, "Failed to export database.");
        sqlite3_close(fileDB);
        return FALSE;
    }

    // Proceed backup procedure
    sqlite3_backup *backup = sqlite3_backup_init(fileDB, "main", db, "main");

    if (!backup) {
        log_message(ERROR, "Failed to export database.");
        return -1;
    }

    sqlite3_backup_step(backup, -1);
    sqlite3_backup_finish(backup);

    log_message(SUCCESS, "Database exported successully!");
    return 0;
}

/*
    Create note in a diary. Returns new note_id on success or -1 if failed.
*/
int create_note(sqlite3* db) {
    // SQLite command to insert a new empty note and return the note_id
    const char *insert_sql = "INSERT INTO notes(title, body, date, created_at) VALUES('', '', CURRENT_DATE, CURRENT_TIMESTAMP); SELECT last_insert_rowid();";
    
    // Execute the insert command
    if (sqlite3_exec(db, insert_sql, 0, 0, NULL) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        return -1;
    } 

    // Get the last inserted row ID(note_id)
    return sqlite3_last_insert_rowid(db);
}

/*
    Remove note by given note_id from diary.
*/
bool remove_note(sqlite3* db, int note_id) {
    // SQLite command to remove a note based on note_id
    const char *remove_from_notes_sql = "DELETE FROM notes WHERE note_id = ?;";
    sqlite3_stmt* remove_from_notes_stmt;

    if (sqlite3_prepare_v2(db, remove_from_notes_sql, -1, &remove_from_notes_stmt, 0) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    // Bind the note_id parameter
    if (sqlite3_bind_int(remove_from_notes_stmt, 1, note_id) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(remove_from_notes_stmt);
        return FALSE;
    }

    // Execute the remove command
    if (sqlite3_step(remove_from_notes_stmt) != SQLITE_DONE) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(remove_from_notes_stmt);
        return FALSE;
    }

    // Finalize the statement for removing from notes
    if (sqlite3_finalize(remove_from_notes_stmt) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    // SQLite command to remove files based on note_id
    const char *remove_from_files_sql = "DELETE FROM files WHERE note_id = ?;";
    sqlite3_stmt* remove_from_files_stmt = NULL;

    if (sqlite3_prepare_v2(db, remove_from_files_sql, -1, &remove_from_files_stmt, 0) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    // Bind the note_id parameter
    if (sqlite3_bind_int(remove_from_files_stmt, 1, note_id) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(remove_from_files_stmt);
        return FALSE;
    }

    // Execute the remove command
    if (sqlite3_step(remove_from_files_stmt) != SQLITE_DONE) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(remove_from_files_stmt);
        return FALSE;
    }

    // Finalize the statement for removing from files
    if (sqlite3_finalize(remove_from_files_stmt) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    log_message(SUCCESS, "Note id: %d deleted successfully!", note_id);
    return TRUE;
}

/*
    Update note title.
*/
bool set_note_title(sqlite3* db, int note_id, const char* new_title) {
    const char *set_title_sql = "UPDATE notes SET title = ? WHERE note_id = ?;";

    sqlite3_stmt* set_title_stmt = NULL;

    if (sqlite3_prepare_v2(db, set_title_sql, -1, &set_title_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    if (sqlite3_bind_text(set_title_stmt, 1, new_title, strlen(new_title), SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(set_title_stmt, 2, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(set_title_stmt);
        return FALSE;
    }

    if (sqlite3_step(set_title_stmt) != SQLITE_DONE) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(set_title_stmt);
        return FALSE;
    }

    sqlite3_finalize(set_title_stmt);
    return TRUE;
}

/*
    Update note body.
*/
bool set_note_body(sqlite3* db, int note_id, const char* new_body) {
    const char *set_body_sql = "UPDATE notes SET body = ? WHERE note_id = ?;";

    sqlite3_stmt* set_body_stmt = NULL;

    if (sqlite3_prepare_v2(db, set_body_sql, -1, &set_body_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    if (sqlite3_bind_text(set_body_stmt, 1, new_body, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(set_body_stmt, 2, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(set_body_stmt);
        return FALSE;
    }

    if (sqlite3_step(set_body_stmt) != SQLITE_DONE) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(set_body_stmt);
        return FALSE;
    }

    sqlite3_finalize(set_body_stmt);
    return TRUE;
}

/*
    Get note title. Returns note title on success or NULL on failure.
*/
static char* get_note_title(sqlite3* db, int note_id) {
    const char *get_title_sql = "SELECT title FROM notes WHERE note_id = ?;";

    sqlite3_stmt* get_title_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_title_sql, -1, &get_title_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_title_stmt, 1, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_title_stmt);
        return NULL;
    }

    if (sqlite3_step(get_title_stmt) != SQLITE_ROW) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_title_stmt);
        return NULL;
    }

    char* title = strdup((const char*)sqlite3_column_text(get_title_stmt, 0));

    sqlite3_finalize(get_title_stmt);
    return title;
}

/*
    Get note body. Returns note body on success or NULL on failure.
*/
static char* get_note_body(sqlite3* db, int note_id) {
    const char *get_body_sql = "SELECT body FROM notes WHERE note_id = ?;";

    sqlite3_stmt* get_body_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_body_sql, -1, &get_body_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_body_stmt, 1, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_body_stmt);
        return NULL;
    }

    if (sqlite3_step(get_body_stmt) != SQLITE_ROW) {
        log_message(ERROR, "No note found with the given note_id.");
        sqlite3_finalize(get_body_stmt);
        return NULL;
    }

    char* body = strdup((const char*)sqlite3_column_text(get_body_stmt, 0));

    sqlite3_finalize(get_body_stmt);
    return body;
}

/*
    Get note creation date. Returns note creation date on success or NULL on failure.
*/
static char* get_note_date(sqlite3* db, int note_id) {
    const char *get_date_sql = "SELECT created_at FROM notes WHERE note_id = ?";

    sqlite3_stmt* get_date_stmt;

    if (sqlite3_prepare_v2(db, get_date_sql, -1, &get_date_stmt, NULL) != 0) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_date_stmt, 1, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_date_stmt);
        return NULL;
    }

    if (sqlite3_step(get_date_stmt) != SQLITE_ROW) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_date_stmt);
        return NULL;
    }

    char* date = strdup((const char*)sqlite3_column_text(get_date_stmt, 0));

    sqlite3_finalize(get_date_stmt);
    return date;
}

/*
    Get attached file name. Returns filename on success or NULL on failure.
*/
static char* get_filename(sqlite3* db, int file_id) {
    const char *get_filename_sql = "SELECT filename FROM files WHERE file_id = ?;";

    sqlite3_stmt* get_filename_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_filename_sql, -1, &get_filename_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_filename_stmt, 1, file_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_filename_stmt);
        return NULL;
    }

    if (sqlite3_step(get_filename_stmt) != SQLITE_ROW) {
        log_message(ERROR, "No files found with the given file_id.");
        sqlite3_finalize(get_filename_stmt);
        return NULL;
    }

    char* filename = strdup((const char*)sqlite3_column_text(get_filename_stmt, 0));

    sqlite3_finalize(get_filename_stmt);
    return filename;
}

/*
    Get attached file mime-type. Returns mime-type on success or NULL on failure.
*/
static char* get_file_type(sqlite3* db, int file_id) {
    const char *get_file_type_sql = "SELECT type FROM files WHERE file_id = ?;";

    sqlite3_stmt* get_file_type_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_file_type_sql, -1, &get_file_type_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_file_type_stmt, 1, file_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_file_type_stmt);
        return NULL;
    }

    if (sqlite3_step(get_file_type_stmt) != SQLITE_ROW) {
        log_message(ERROR, "No files found with the given file_id.");
        sqlite3_finalize(get_file_type_stmt);
        return NULL;
    }

    char* file_type = strdup((const char*)sqlite3_column_text(get_file_type_stmt, 0));

    sqlite3_finalize(get_file_type_stmt);
    return file_type;
}

/*
    Get attached file size. Returns size on success or -1 on failure.
*/
static size_t get_file_size(sqlite3* db, int file_id) {
    const char *get_file_size_sql = "SELECT size FROM files WHERE file_id = ?;";

    sqlite3_stmt* get_file_size_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_file_size_sql, -1, &get_file_size_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return -1;
    }

    if (sqlite3_bind_int(get_file_size_stmt, 1, file_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_file_size_stmt);
        return -1;
    }

    if (sqlite3_step(get_file_size_stmt) != SQLITE_ROW) {
        log_message(ERROR, "No files found with the given file_id.");
        sqlite3_finalize(get_file_size_stmt);
        return -1;
    }

    size_t file_size = sqlite3_column_int(get_file_size_stmt, 0);

    sqlite3_finalize(get_file_size_stmt);
    return file_size;
}

// Currently unused, but will be in future (hopefully...)
// static char* get_file_hash(sqlite3* db, int file_id) {
//     const char *get_file_hash_sql = "SELECT hash FROM files WHERE file_id = ?;";

//     sqlite3_stmt* get_file_hash_stmt = NULL;

//     if (sqlite3_prepare_v2(db, get_file_hash_sql, -1, &get_file_hash_stmt, 0) != SQLITE_OK) {
//         print_message(ERROR, sqlite3_errmsg(db));
//         return NULL;
//     }

//     if (sqlite3_bind_int(get_file_hash_stmt, 1, file_id) != SQLITE_OK) {
//         print_message(ERROR, sqlite3_errmsg(db));
//         sqlite3_finalize(get_file_hash_stmt);
//         return NULL;
//     }

//     if (sqlite3_step(get_file_hash_stmt) != SQLITE_ROW) {
//         // Handle the case where no rows are found
//         print_message(ERROR, "No files found with the given file_id.");
//         sqlite3_finalize(get_file_hash_stmt);
//         return NULL;
//     }

//     char* file_hash = strdup((const char*)sqlite3_column_text(get_file_hash_stmt, 0));

//     sqlite3_finalize(get_file_hash_stmt);
//     return file_hash;
// }

/*
    Get file attachment date. Returns date on success or NULL on failure.
*/
static char* get_file_date(sqlite3* db, int file_id) {
    const char *get_file_date_sql = "SELECT created_at FROM files WHERE file_id = ?;";

    sqlite3_stmt* get_file_date_stmt = NULL;

    if (sqlite3_prepare_v2(db, get_file_date_sql, -1, &get_file_date_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_file_date_stmt, 1, file_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_file_date_stmt);
        return NULL;
    }

    if (sqlite3_step(get_file_date_stmt) != SQLITE_ROW) {
        log_message(ERROR, "No files found with the given file_id.");
        sqlite3_finalize(get_file_date_stmt);
        return NULL;
    }

    char* file_date = strdup((const char*)sqlite3_column_text(get_file_date_stmt, 0));

    sqlite3_finalize(get_file_date_stmt);
    return file_date;
}

static GArray* get_notes_id(sqlite3* db) {
    // Get array of existing note(s)_id
    const char* get_notes_id_sql = "SELECT DISTINCT note_id FROM notes";

    sqlite3_stmt* get_notes_id_stmt;

    if (sqlite3_prepare_v2(db, get_notes_id_sql, -1, &get_notes_id_stmt, NULL) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    // Create a GArray to store note(s)_id
    GArray* notes_id = g_array_new(FALSE, FALSE, sizeof(int));

    // Retrieve note(s)_id
    while (sqlite3_step(get_notes_id_stmt) == SQLITE_ROW) {
        int note_id = sqlite3_column_int(get_notes_id_stmt, 0);
        g_array_append_val(notes_id, note_id);
    }

    sqlite3_finalize(get_notes_id_stmt);
    return notes_id;
}

static GArray* get_attached_files_id_by_note_id(sqlite3* db, int note_id) {
    // Get attached file(s)_id by note_id
    const char* get_attached_files_id_sql = "SELECT DISTINCT file_id FROM files WHERE note_id = ?;";

    sqlite3_stmt* get_attached_files_id_stmt;

    if (sqlite3_prepare_v2(db, get_attached_files_id_sql, -1, &get_attached_files_id_stmt, NULL) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return NULL;
    }

    if (sqlite3_bind_int(get_attached_files_id_stmt, 1, note_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(get_attached_files_id_stmt);
        return NULL;
    }

    // Create a GArray to store attached_file(s)_id
    GArray* attached_files_id = g_array_new(FALSE, FALSE, sizeof(int));

    // Retrieve attached file(s)_id
    while (sqlite3_step(get_attached_files_id_stmt) == SQLITE_ROW) {
        int file_id = sqlite3_column_int(get_attached_files_id_stmt, 0);
        g_array_append_val(attached_files_id, file_id);
    }

    sqlite3_finalize(get_attached_files_id_stmt);
    return attached_files_id;
}

// int free_garray (GArray* array) {
//     if (!array) {
//         print_message(ERROR, "Invalid GArray, failed to free.");
//         return -1;
//     }

//     // https://docs.gtk.org/glib/type_func.Array.free.html
//     if (g_array_free(array, TRUE) != NULL) {
//         print_message(ERROR, "g_array_free returned not null, this is not good.");
//         return -1;
//     }

//     return 0;
// }

/*
    Attach file to note.
*/
bool attach_file_to_note(sqlite3* db, const int note_id, const char* path) {
    // read file name
    char* filename = basename((char*) path);

    FILE *fp_t;
    fp_t= fopen(path, "rb");
    if (fp_t== NULL) {
        log_message(ERROR, "Error opening file %s", path);
        return FALSE;
    }

    // get file size
    fseek(fp_t, 0, SEEK_END);
    size_t file_size = ftell(fp_t);
    fseek(fp_t, 0, SEEK_SET);

    // read binary data from file
    g_autofree unsigned char *binary_data =(unsigned char*)malloc(file_size);
    if (binary_data == NULL) {
        log_message(ERROR, "Memory allocation failed.");
        fclose(fp_t);
        return FALSE;
    }

    if (fread(binary_data, 1, file_size, fp_t) !=(size_t)file_size) {
        log_message(ERROR, "Failed to read file content.");
        fclose(fp_t);
        return FALSE;
    }

    fclose(fp_t);

    // get mime type of the file
    gboolean is_certain = FALSE;
    g_autofree char* mime_type = g_content_type_guess(filename, binary_data, file_size, &is_certain);

    if (mime_type == NULL) {
        log_message(ERROR, "Failed to read file mime-type.");
        mime_type = "application/octet-stream\0";
    }

    // generate file hash
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, binary_data, file_size);

    // add file to the db
    const char *attach_file_sql = "INSERT INTO files(note_id, filename, type, size, binary_data, hash, created_at) VALUES(?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP); SELECT last_insert_rowid();";
    sqlite3_stmt* attach_file_stmt = NULL;

    if (sqlite3_prepare_v2(db, attach_file_sql, -1, &attach_file_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    if (sqlite3_bind_int(attach_file_stmt, 1, note_id) != SQLITE_OK ||
        sqlite3_bind_text(attach_file_stmt, 2, filename, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(attach_file_stmt, 3, mime_type, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(attach_file_stmt, 4, file_size) != SQLITE_OK ||
        sqlite3_bind_blob(attach_file_stmt, 5, binary_data, file_size, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(attach_file_stmt, 6, (const char*) hash, -1, SQLITE_STATIC) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    if (sqlite3_step(attach_file_stmt) != SQLITE_DONE) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    // free(binary_data);

    sqlite3_finalize(attach_file_stmt);

    log_message(SUCCESS, "File \"%s\" attached successfully!", filename);
    return sqlite3_last_insert_rowid(db);
}

/*
    Export file from note to given path. Used in exporting files by user, and opening files in tmp storage.
*/
static bool export_file_to_path(sqlite3* db, const int file_id, const char* path) {
    FILE *fp_t;
    fp_t = fopen(path, "wb");
    if (fp_t == NULL) {
        log_message(ERROR, "Error creating file %s", path);
        return FALSE;
    }

    // add file to the db
    const char *export_file_sql = "SELECT binary_data FROM files WHERE file_id = ?;";

    sqlite3_stmt* export_file_stmt = NULL;

    if (sqlite3_prepare_v2(db, export_file_sql, -1, &export_file_stmt, 0) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        return FALSE;
    }

    if (sqlite3_bind_int(export_file_stmt, 1, file_id) != SQLITE_OK) {
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(export_file_stmt);
        return FALSE;
    }

    if (sqlite3_step(export_file_stmt) != SQLITE_ROW) {  // Check for ROW, not DONE
        log_message(ERROR, sqlite3_errmsg(db));
        sqlite3_finalize(export_file_stmt);
        return FALSE;
    }

    // Retrieve the BLOB data and 
    const void *blobData = sqlite3_column_blob(export_file_stmt, 0);
    int blobSize = sqlite3_column_bytes(export_file_stmt, 0);

    // Write blob to the file
    fwrite(blobData, 1, blobSize, fp_t);
    fclose(fp_t);

    sqlite3_finalize(export_file_stmt);

    return TRUE;
}

/*
    Export file to given path
*/
bool export_file(sqlite3* db, const int file_id, const char* target_folder) {
    g_autofree char* filename = get_filename(db, file_id);

    char file_path[100];

    // Workaround for case when user sends empty folder_path (for exporting in a running folder (probably wont be used))
    if (target_folder != NULL && target_folder[0] != '\0') {
        snprintf(file_path, sizeof(file_path), "%s/%s", target_folder, filename);
    } else {
        snprintf(file_path, sizeof(file_path), filename);
    }

    // free(filename);

    if (!export_file_to_path(db, file_id, file_path)) {
        log_message(ERROR, "File export failed!");
        return FALSE;
    }

    log_message(SUCCESS, "File exported successfully!");

    return TRUE;
}

/*
    Open file in tmp storage.
*/
 bool open_tmp_file(sqlite3* db, const int file_id) {
    g_autofree char* filename = get_filename(db, file_id);

    char target_path[100];
    file_uri_path_builder(target_path, sizeof(target_path), g_path_get_dirname(sqlite3_db_filename(db, "main")), filename);

    g_autofree char *uri = g_strdup_printf("file://%s", target_path);

    if (!export_file_to_path(db, file_id, target_path)) {
        log_message(ERROR, "Failed to export file to tmp storage.");
        return FALSE;
    }

    GAppLaunchContext *context;
    g_autofree GError *error = NULL;
    context = g_app_launch_context_new();

    // Launch default app for the given URI
    g_app_info_launch_default_for_uri(uri, context, &error);
    if (error != NULL) {
        log_message(ERROR, "Error launching default app: %s", error->message);
    }

    return TRUE;
}

/*
    Get diary data in JSON format.
*/
char* get_notes_json(sqlite3* db) {
    clock_t start_time, end_time;
    double cpu_time_used;
    start_time = clock();

    cJSON* root = cJSON_CreateObject();

    g_autofree GArray* notes_id = get_notes_id(db);

    cJSON* notes = cJSON_AddArrayToObject(root, "notes");

    for (int i=0; i<notes_id->len; i++) {
        cJSON *note = cJSON_CreateObject();

        int note_id = g_array_index(notes_id, int, i);
        g_autofree char* title = get_note_title(db, note_id);
        g_autofree char* body = get_note_body(db, note_id);
        g_autofree char* date = get_note_date(db, note_id);

        cJSON_AddNumberToObject(note, "note_id", note_id);
        cJSON_AddStringToObject(note, "title", title);
        cJSON_AddStringToObject(note, "body", body);
        cJSON_AddStringToObject(note, "created_at", date);

        cJSON* files = cJSON_AddArrayToObject(note, "files");

        g_autofree GArray* attached_files_id = get_attached_files_id_by_note_id(db, note_id);

        if (attached_files_id != NULL) {
            for (int j=0; j<attached_files_id->len; j++) {
                cJSON *file = cJSON_CreateObject();

                int file_id = g_array_index(attached_files_id, int, j);
                g_autofree char* filename = get_filename(db, file_id);
                g_autofree char* file_type = get_file_type(db, file_id);
                size_t file_size = get_file_size(db, file_id);
                g_autofree char* file_date = get_file_date(db, file_id);

                cJSON_AddNumberToObject(file, "file_id", file_id);
                cJSON_AddStringToObject(file, "filename", filename);
                cJSON_AddStringToObject(file, "type", file_type);
                cJSON_AddNumberToObject(file, "size", file_size);
                cJSON_AddStringToObject(file, "created_at", file_date);

                cJSON_AddItemToArray(files, file);
            }
        }

        cJSON_AddItemToArray(notes, note);
    }

    // Serialize the JSON object to a string
    char* jsonString = cJSON_Print(root);

    // Free allocated memory
    cJSON_Delete(root);

    end_time = clock();
    cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
    log_message(DEBUG, "Execution Time: %f seconds", cpu_time_used);

    return jsonString;
}