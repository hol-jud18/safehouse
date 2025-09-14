import gi
import os
from datetime import datetime

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

VAULT_DATA = os.path.join(os.path.dirname(__file__), "../vault-command-utility/vault-data")

class VaultViewer(Gtk.Window):
    def __init__(self):
        super().__init__(title="Vault Viewer")
        self.set_default_size(500, 300)

        # vertical layout
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        # file list
        self.liststore = Gtk.ListStore(str, str, str)  # name, size, date
        treeview = Gtk.TreeView(model=self.liststore)

        for i, col_title in enumerate(["File", "Size (KB)", "Modified"]):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(col_title, renderer, text=i)
            treeview.append_column(column)

        vbox.pack_start(treeview, True, True, 0)

        # refresh button
        button = Gtk.Button(label="Refresh")
        button.connect("clicked", self.on_refresh)
        vbox.pack_start(button, False, False, 0)

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


def main():
    win = VaultViewer()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()
