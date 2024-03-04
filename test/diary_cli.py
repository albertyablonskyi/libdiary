import cmd
from getpass import getpass
import diary

class DiaryCLI(cmd.Cmd):
    prompt = "diary> "
    intro = "\nWelcome to the libdiary CLI. Type 'help' for a list of commands."

    def __init__(self):
        super().__init__()
        self.diary = None

    def do_create_diary(self, args):
        """Create a new diary."""
        self.diary = diary.Diary()
        if (self.diary.create_diary()):
            print("Diary created.")
        else: print("Failed to create diary.")

    def do_open_diary(self, args):
        """Open an existing diary file with password."""
        self.diary = diary.Diary()
        path = input("Enter the diary path: ")
        password = getpass("Enter the password: ")
        if (self.diary.open_diary(path, password)):
            print(f"Diary opened from {path}.")
        else: print(f"Failed to open diary {path}")

    def do_save_diary(self, args):
        """Save the diary to a file with password protection."""
        path = input("Enter the save path: ")
        password = getpass("Enter a password: ")
        if (self.diary.save_diary(path, password)):
            print(f"Diary saved to {path} with password protection.")
        else: print(f"Failed to save diary to {path}")

    def do_export_database(self, args):
        """Export diary database to a file."""
        path = input("Enter the export path: ")
        if (self.diary.export_database(path)):
            print(f"Diary database exported to {path}.")
        else: print(f"Failed to export database to {path}")

    def do_create_note(self, args):
        """Create a new diary note."""
        note_id = self.diary.create_note()
        if (note_id != -1):
            print(f"Note created with ID: {note_id}")
        else: print("Failed to create new note.")

    def do_remove_note(self, args):
        """Remove a diary note by ID."""
        note_id = input("Enter note_id to remove: ")
        if (self.diary.remove_note(note_id)):
            print(f"Note {note_id} removed.")
        else: print(f"Failed to remove note {note_id}")

    def do_set_title(self, args):
        """Set a new title for a diary note by ID."""
        note_id = input("Enter a note_id: ")
        title = input("Enter a title: ")
        if (self.diary.set_note_title(note_id, title)):
            print(f"Title for note {note_id} set to {title}.")
        else: print(f"Failed to set title for {note_id}")

    def do_set_body(self, args):
        """Set a new body for a diary note by ID."""
        note_id = input("Enter a note_id: ")
        body = input("Enter a body: ")
        if (self.diary.set_note_body(note_id, body)):
            print(f"Body for note {note_id} set to {body}.")
        else: print(f"Failed to set body for {note_id}")

    def do_attach_file(self, args):
        """Attach file to a diary note by ID."""
        path = input("Enter the file path: ")
        note_id = input("Enter a note_id: ")        
        file_id = self.diary.attach_file(note_id, path)
        if (file_id != -1):
            print(f"File {path} attached with {file_id}.")
        else: print("Failed to attach file.")

    def do_export_file(self, args):
        """Export file to a file by file ID."""
        path = input("Enter the file path: ")
        file_id = input("Enter a file_id: ")        
        if (self.diary.export_file(file_id, path)):
            print("File exported successfully.")
        else: print("Failed to export file.")

    def do_open_file(self, args):
        """Export file to a file by file ID."""
        file_id = input("Enter a file_id: ")        
        if (self.diary.open_tmp_file(file_id)):
            print("File opened successfully.")
        else: print("Failed to open file.")

    def do_get_notes_json(self, args):
        """Get note in json"""
        json = self.diary.get_notes_json()
        print(json)

    def do_exit(self, args):
        """Exit the diary CLI."""
        print("Exiting the libdiary CLI.")
        return True
    
if __name__ == "__main__":
    DiaryCLI().cmdloop()
