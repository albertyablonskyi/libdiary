from ctypes import *
import json

class Diary:
    def __init__(self):
        self.libdiary = CDLL("/usr/local/lib64/libdiary.so")

        # db connection instance
        self.diary_instance = None

        # create_diary()
        self.libdiary.create_diary.restype = c_void_p

        # open_diary()
        self.libdiary.open_diary.argtypes = [c_char_p, c_char_p]
        self.libdiary.open_diary.restype = c_void_p

        # save_diary()
        self.libdiary.save_diary.argtypes = [c_void_p, c_char_p, c_char_p]
        self.libdiary.save_diary.restype = c_bool

        # export_database()
        self.libdiary.export_database.argtypes = [c_void_p, c_char_p]
        self.libdiary.export_database.restype = c_bool

        # create_note()
        self.libdiary.create_note.argtypes = [c_void_p]
        self.libdiary.create_note.restype = c_int

        # remove_note()
        self.libdiary.remove_note.argtypes = [c_void_p, c_int]
        self.libdiary.remove_note.restype = c_bool

        # set_note_title()
        self.libdiary.set_note_title.argtypes = [c_void_p, c_int, c_char_p]
        self.libdiary.set_note_title.restype = c_bool

        # set_note_body()
        self.libdiary.set_note_body.argtypes = [c_void_p, c_int, c_char_p]
        self.libdiary.set_note_body.restype = c_bool

        # attach_file_to_note()
        self.libdiary.attach_file_to_note.argtypes = [c_void_p, c_int, c_char_p]
        self.libdiary.attach_file_to_note.restype = c_bool

        # export_file()
        self.libdiary.export_file.argtypes = [c_void_p, c_int, c_char_p]
        self.libdiary.export_file.restype = c_bool

        # open_tmp_file()
        self.libdiary.open_tmp_file.argtypes = [c_void_p, c_int]
        self.libdiary.open_tmp_file.restype = c_bool

        # get_notes_json()
        self.libdiary.get_notes_json.argtypes = [c_void_p]
        self.libdiary.get_notes_json.restype = c_char_p

        # cleanup()
        self.libdiary.cleanup.argtypes = [c_void_p]
        self.libdiary.cleanup.restype = int

    def __del__(self):
        if (self.diary_instance is not None):
            self.libdiary.cleanup(self.diary_instance)

    def decode_string(self, string):
        return string.decode("utf-8")

    def encode_string(self, string):
        return string.encode("utf-8")
    
    def create_diary(self):
        self.diary_instance = self.libdiary.create_diary()
        if (self.diary_instance):
            return True
        else: return False

    def open_diary(self, path, password):
        self.diary_instance = self.libdiary.open_diary(self.encode_string(path), self.encode_string(password))
        if (self.diary_instance):
            return True
        else: return False
    
    def save_diary(self, path, password):
        return self.libdiary.save_diary(self.diary_instance, self.encode_string(path), self.encode_string(password))

    def export_database(self, path):
        return self.libdiary.export_database(self.diary_instance, self.encode_string(path))

    def create_note(self):
        return self.libdiary.create_note(self.diary_instance)
    
    def remove_note(self, note_id):
        return self.libdiary.remove_note(self.diary_instance, int(note_id))

    def set_note_title(self, note_id, new_title):
        return self.libdiary.set_note_title(self.diary_instance, int(note_id), self.encode_string(new_title))

    def set_note_body(self, note_id, new_body):
        return self.libdiary.set_note_body(self.diary_instance, int(note_id), self.encode_string(new_body))

    def attach_file(self, note_id, path):
        return self.libdiary.attach_file_to_note(self.diary_instance, int(note_id), self.encode_string(path))

    def export_file(self, file_id, path):
        return self.libdiary.export_file(self.diary_instance, int(file_id), self.encode_string(path))
    
    def open_tmp_file(self, file_id):
        return self.libdiary.open_tmp_file(self.diary_instance, int(file_id))

    def get_notes_json(self):
        json_string = self.libdiary.get_notes_json(self.diary_instance)
        json_object = json.loads(json_string)
        return json_object
