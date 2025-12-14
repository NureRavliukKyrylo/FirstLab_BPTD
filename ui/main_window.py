import tkinter as tk
from ui.tabs.encrypt_tab import EncryptTab
from ui.tabs.key_tab import KeyTab

class MainWindow(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#F6F7FB")
        self.pack(fill="both", expand=True)
        self._build()

    def _build(self):
        header = tk.Frame(self, bg="#FFFFFF", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="Laboratory work No. 1",
            bg="#FFFFFF",
            fg="#111111",
            font=("EXO2", 22, "bold")
        ).pack(side="left", padx=32)

        body = tk.Frame(self, bg="#F6F7FB")
        body.pack(fill="both", expand=True, padx=24, pady=24)

        self._build_tabs(body)

        self.content = tk.Frame(body, bg="#F6F7FB")
        self.content.pack(fill="both", expand=True, pady=(24, 0))

        self.tabs = {
            "Encryption": EncryptTab(self.content),
            "Key Analysis": KeyTab(self.content)
        }

        self._show_tab("Encryption")

    def _build_tabs(self, parent):
        wrapper = tk.Frame(parent, bg="#F6F7FB")
        wrapper.pack(anchor="w")

        self.tab_buttons = {}

        for name in ["Encryption", "Key Analysis"]:
            btn = tk.Label(
                wrapper,
                text=name,
                bg="#E5E7EB",
                fg="#111111",
                padx=20,
                pady=8,
                font=("Inter", 11, "bold"),
                cursor="hand2"
            )
            btn.pack(side="left", padx=6)
            btn.bind("<Button-1>", lambda e, n=name: self._show_tab(n))
            self.tab_buttons[name] = btn

    def _show_tab(self, name):
        for tab in self.tabs.values():
            tab.pack_forget()

        for n, btn in self.tab_buttons.items():
            btn.config(
                bg="#000000" if n == name else "#E5E7EB",
                fg="#FFFFFF" if n == name else "#111111"
            )

        self.tabs[name].pack(fill="both", expand=True)
