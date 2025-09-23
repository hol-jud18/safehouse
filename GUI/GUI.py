import gi
import os
from datetime import datetime
import subprocess
from gi.repository import Gtk

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

VAULT_DATA = os.path.join(os.path.dirname(__file__), "../vault-command-utility/vault-data")

class VaultViewer(Gtk.Window):
    def __init__(self):
        super().__init__(title="Vault Viewer")
        self.set_default_size(500, 300)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        # file list
        self.liststore = Gtk.ListStore(str, str, str)  # name, size, date
        self.treeview = Gtk.TreeView(model=self.liststore)

        for i, col_title in enumerate(["File", "Size (KB)", "Modified"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(col_title, renderer, text=i)
            self.treeview.append_column(column)

        vbox.pack_start(self.treeview, True, True, 0)

        # button row
        hbox = Gtk.Box(spacing=6)
        vbox.pack_start(hbox, False, False, 0)

        refresh_button = Gtk.Button(label="Refresh")
        refresh_button.connect("clicked", self.on_refresh)
        hbox.pack_start(refresh_button, False, False, 0)

        retrieve_button = Gtk.Button(label="Retrieve")
        retrieve_button.connect("clicked", self.on_retrieve)
        hbox.pack_start(retrieve_button, False, False, 0)

        self.populate()

    def populate(self):
        self.liststore.clear()
        if os.path.exists(VAULT_DATA):
            for filename in os.listdir(VAULT_DATA):
                path = os.path.join(VAULT_DATA, filename)
                if os.path.isfile(path):
                    size = os.path.getsize(path) // 1024
                    mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
                    self.liststore.append([filename, str(size), mtime])

    def on_refresh(self, widget):
        self.populate()

    def on_retrieve(self, widget):
        selection = self.treeview.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is None:
            self.show_message("No file selected.", Gtk.MessageType.WARNING)
            return

        filename = model[treeiter][0]
        filepath = os.path.join(VAULT_DATA, filename)

        # ask for password
        dialog = Gtk.Dialog("Enter Password", self, 0,
                            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                             Gtk.STOCK_OK, Gtk.ResponseType.OK))
        entry = Gtk.Entry()
        entry.set_visibility(False)  # hide text
        entry.set_placeholder_text("Password")
        box = dialog.get_content_area()
        box.add(entry)
        dialog.show_all()

        response = dialog.run()
        password = entry.get_text() if response == Gtk.ResponseType.OK else None
        dialog.destroy()

        if not password:
            return

        # run vault CLI
        try:
            subprocess.run(
                ["../vault-command-utility/vault", filepath, "--retrieve", "--key", password],
                check=True
            )
            self.show_message(f"Retrieved {filename}", Gtk.MessageType.INFO)
        except subprocess.CalledProcessError:
            self.show_message("Retrieve failed (bad password or integrity error).", Gtk.MessageType.ERROR)

    def show_message(self, text, msg_type):
        dialog = Gtk.MessageDialog(
            self, 0, msg_type, Gtk.ButtonsType.OK, text
        )
        dialog.run()
        dialog.destroy()



def main():
    win = VaultViewer()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()
