import tkinter as tk
from analysis import is_weak_key
from ui.utils.validators import parse_des_key

class KeyTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#F6F7FB")
        self._build()

    def _build(self):
        container = tk.Frame(self, bg="#F6F7FB")
        container.pack(fill="both", expand=True, padx=32, pady=32)

        tk.Label(
            container,
            text="Key Analysis",
            bg="#F6F7FB",
            fg="#111111",
            font=("Inter", 20, "bold")
        ).pack(anchor="w", pady=(0, 24))

        card = tk.Frame(container, bg="#FFFFFF")
        card.pack(fill="x")

        tk.Label(
            card,
            text="DES Key (64-bit integer or hexadecimal)",
            bg="#FFFFFF",
            fg="#6B7280",
            font=("Inter", 10, "bold")
        ).pack(anchor="w", padx=24, pady=(20, 4))

        self.key_input = tk.Entry(
            card,
            font=("Inter", 11),
            bg="#F9FAFB",
            bd=0,
            highlightthickness=1,
            highlightbackground="#E5E7EB"
        )
        self.key_input.pack(fill="x", padx=24, pady=(0, 16))

        tk.Button(
            card,
            text="Analyze Key",
            bg="#111827",
            fg="#FFFFFF",
            bd=0,
            padx=24,
            pady=10,
            font=("Inter", 11, "bold"),
            command=self._analyze
        ).pack(anchor="w", padx=24, pady=(0, 20))

        tk.Frame(card, bg="#E5E7EB", height=1).pack(fill="x", padx=24)

        tk.Label(
            card,
            text="Analysis Result",
            bg="#FFFFFF",
            fg="#6B7280",
            font=("Inter", 10, "bold")
        ).pack(anchor="w", padx=24, pady=(16, 4))

        self.result = tk.Text(
            card,
            height=7,
            font=("Inter", 11),
            bg="#F9FAFB",
            bd=0,
            highlightthickness=1,
            highlightbackground="#E5E7EB",
            state="disabled"
        )
        self.result.pack(fill="x", padx=24, pady=(0, 24))

    def _set_result(self, text):
        self.result.config(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", text)
        self.result.config(state="disabled")

    def _analyze(self):
        key_text = self.key_input.get().strip()

        try:
            key64 = parse_des_key(key_text)
        except ValueError as e:
            self._set_result(f"Input error:\n{e}")
            return

        weak, explanation = is_weak_key(key64)

        if weak:
            title = "Key Status: WEAK"
            recommendation = "This key should not be used for encryption."
        else:
            title = "Key Status: NORMAL"
            recommendation = "This key is suitable for DES encryption."

        output = (
            f"{title}\n\n"
            f"Details:\n{explanation}\n\n"
            f"Recommendation:\n{recommendation}"
        )

        self._set_result(output)
