"""Simple Tkinter-based GUI for theZoo malware repository."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Tuple

from imports.db_handler import DBHandler


class TheZooGUI:
    """Minimal graphical interface for browsing malware metadata."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("theZoo GUI")
        self.root.geometry("900x520")

        self.db = DBHandler()
        self.malware_rows: List[Tuple] = []

        self._build_layout()
        self._load_data()

    def _build_layout(self) -> None:
        main_frame = ttk.Frame(self.root, padding=16)
        main_frame.pack(fill=tk.BOTH, expand=True)

        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        search_entry.bind("<KeyRelease>", self._filter_rows)

        columns = ("ID", "TYPE", "LANGUAGE", "ARCH", "PLATFORM", "NAME")
        self.tree = ttk.Treeview(
            main_frame,
            columns=columns,
            show="headings",
            height=15,
        )

        for col in columns:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=120 if col != "NAME" else 220, anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(12, 0))

        self.details_button = ttk.Button(
            button_frame,
            text="Show Details",
            command=self._show_selected_details,
            state=tk.DISABLED,
        )
        self.details_button.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Loaded 0 entries")
        ttk.Label(button_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

    def _load_data(self) -> None:
        try:
            self.malware_rows = self.db.get_partial_details()
        except Exception as exc:  # pragma: no cover - defensive UI code
            messagebox.showerror("Database Error", str(exc))
            self.malware_rows = []
        finally:
            self._refresh_tree(self.malware_rows)

    def _refresh_tree(self, rows: List[Tuple]) -> None:
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            self.tree.insert("", tk.END, iid=str(row[0]), values=row)
        self.status_var.set(f"Loaded {len(rows)} entries")
        self.details_button.configure(state=tk.DISABLED)

    def _filter_rows(self, _event: tk.Event) -> None:
        text = self.search_var.get().strip().lower()
        if not text:
            self._refresh_tree(self.malware_rows)
            return

        filtered = [
            row for row in self.malware_rows
            if any(text in str(value).lower() for value in row)
        ]
        self._refresh_tree(filtered)

    def _on_select(self, _event: tk.Event) -> None:
        has_selection = bool(self.tree.selection())
        new_state = tk.NORMAL if has_selection else tk.DISABLED
        self.details_button.configure(state=new_state)

    def _show_selected_details(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return

        mal_id = int(selection[0])
        try:
            result = self.db.get_mal_info(mal_id)
        except Exception as exc:  # pragma: no cover - defensive UI code
            messagebox.showerror("Database Error", str(exc))
            return

        if not result:
            messagebox.showinfo("Malware Info", "No additional metadata available.")
            return

        (
            mal_type,
            name,
            version,
            author,
            language,
            date,
            architecture,
            platform,
            tags,
        ) = result[0]

        info_lines = [
            f"Name: {name or 'N/A'}",
            f"Type: {mal_type or 'N/A'}",
            f"Version: {version or 'N/A'}",
            f"Author: {author or 'N/A'}",
            f"Language: {language or 'N/A'}",
            f"Date: {date or 'N/A'}",
            f"Architecture: {architecture or 'N/A'}",
            f"Platform: {platform or 'N/A'}",
            f"Tags: {tags or 'N/A'}",
        ]

        messagebox.showinfo("Malware Info", "\n".join(info_lines))

    def on_close(self) -> None:
        self.db.close_connection()
        self.root.destroy()


def run() -> None:
    root = tk.Tk()
    app = TheZooGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    run()
