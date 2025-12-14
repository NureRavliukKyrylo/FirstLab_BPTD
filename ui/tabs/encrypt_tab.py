import tkinter as tk
import threading
from des_core import des_encrypt, des_decrypt, key_to_bits
from analysis import encrypt_block_and_collect, entropy_binary
from ui.utils.validators import validate_text_key

class EncryptTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#F6F7FB")
        self._entropy_job_id = 0
        self._build()

    def _build(self):
        container = tk.Frame(self, bg="#F6F7FB")
        container.pack(fill="both", expand=True, padx=32, pady=32)

        tk.Label(
            container,
            text="Encryption / Decryption",
            bg="#F6F7FB",
            fg="#111111",
            font=("Inter", 20, "bold")
        ).pack(anchor="w", pady=(0, 24))

        cards = tk.Frame(container, bg="#F6F7FB")
        cards.pack(fill="both", expand=True)

        left = self._card(cards, "Input")
        right = self._card(cards, "Result")

        left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right.pack(side="right", fill="both", expand=True, padx=(16, 0))

        self._input_section(left)
        self._result_section(right)
        self._entropy_section(container)

    def _card(self, master, title):
        card = tk.Frame(master, bg="#FFFFFF")
        tk.Label(card, text=title, bg="#FFFFFF", fg="#111111", font=("Inter", 14, "bold")).pack(anchor="w", padx=24, pady=(20, 12))
        tk.Frame(card, bg="#E5E7EB", height=1).pack(fill="x", padx=24)
        return card

    def _input_section(self, parent):
        c = tk.Frame(parent, bg="#FFFFFF")
        c.pack(fill="both", expand=True, padx=24, pady=16)

        tk.Label(c, text="Plaintext / Ciphertext", bg="#FFFFFF", fg="#6B7280", font=("Inter", 10, "bold")).pack(anchor="w")
        self.text_input = tk.Text(c, height=8, font=("Inter", 11), bg="#F9FAFB", bd=0, highlightthickness=1, highlightbackground="#E5E7EB")
        self.text_input.pack(fill="x", pady=(4, 16))

        tk.Label(c, text="Key", bg="#FFFFFF", fg="#6B7280", font=("Inter", 10, "bold")).pack(anchor="w")
        self.key_input = tk.Entry(c, font=("Inter", 11), bg="#F9FAFB", bd=0, highlightthickness=1, highlightbackground="#E5E7EB")
        self.key_input.pack(fill="x", pady=(4, 20))

        buttons = tk.Frame(c, bg="#FFFFFF")
        buttons.pack(fill="x")

        tk.Button(buttons, text="Encrypt", bg="#111827", fg="#FFFFFF", bd=0, padx=24, pady=10, font=("Inter", 11, "bold"), command=self._encrypt).pack(side="left")
        tk.Button(buttons, text="Decrypt", bg="#E5E7EB", fg="#111111", bd=0, padx=24, pady=10, font=("Inter", 11, "bold"), command=self._decrypt).pack(side="left", padx=(12, 0))

    def _result_section(self, parent):
        c = tk.Frame(parent, bg="#FFFFFF")
        c.pack(fill="both", expand=True, padx=24, pady=16)

        tk.Label(c, text="Output", bg="#FFFFFF", fg="#6B7280", font=("Inter", 10, "bold")).pack(anchor="w")
        self.result_output = tk.Text(c, height=12, font=("Inter", 11), bg="#F9FAFB", bd=0, highlightthickness=1, highlightbackground="#E5E7EB")
        self.result_output.pack(fill="both", expand=True, pady=(4, 0))

    def _entropy_section(self, parent):
        card = tk.Frame(parent, bg="#FFFFFF")
        card.pack(fill="both", pady=(24, 0))

        tk.Label(card, text="Entropy per block and round", bg="#FFFFFF", fg="#111111", font=("Inter", 14, "bold")).pack(anchor="w", padx=24, pady=(20, 12))
        tk.Frame(card, bg="#E5E7EB", height=1).pack(fill="x", padx=24)

        self.entropy_grid = tk.Frame(card, bg="#FFFFFF")
        self.entropy_grid.pack(fill="both", expand=True, padx=24, pady=(16, 24))

    def _clear_entropy_grid(self):
        for w in self.entropy_grid.winfo_children():
            w.destroy()

    def _set_result(self, text):
        self.result_output.delete("1.0", "end")
        self.result_output.insert("1.0", text)

    def _encrypt(self):
        text = self.text_input.get("1.0", "end").strip()
        key_text = self.key_input.get().strip()

        self._entropy_job_id += 1
        job_id = self._entropy_job_id
        self._clear_entropy_grid()

        if not text:
            self._set_result("Input text is required.")
            return

        try:
            validate_text_key(key_text)
        except ValueError as e:
            self._set_result(str(e))
            return

        try:
            result = des_encrypt(text, key_text)
            self._set_result(result)
            threading.Thread(target=self._analyze_entropy_blocks, args=(job_id, text, key_text), daemon=True).start()
        except Exception as e:
            self._set_result(f"Encrypt error: {e}")

    def _decrypt(self):
        ciphertext = self.result_output.get("1.0", "end").strip() or self.text_input.get("1.0", "end").strip()
        key_text = self.key_input.get().strip()

        if not ciphertext:
            self._set_result("Ciphertext is required.")
            return

        try:
            validate_text_key(key_text)
        except ValueError as e:
            self._set_result(str(e))
            return

        try:
            result = des_decrypt(ciphertext, key_text)
            self._set_result(result)
        except Exception as e:
            self._set_result(f"Decrypt error: {e}")

    def _analyze_entropy_blocks(self, job_id, text, key_text):
        try:
            key64 = key_to_bits(key_text)
            data = text.encode("utf-8")
            pad = 8 - (len(data) % 8)
            data += bytes([pad] * pad)

            blocks = []

            for i in range(0, len(data), 8):
                if job_id != self._entropy_job_id:
                    return

                block = int.from_bytes(data[i:i + 8], "big")
                _, round_Rs = encrypt_block_and_collect(block, key64)

                values = []
                for r in range(16):
                    R = round_Rs[r]
                    p = R.bit_count() / 32
                    values.append(entropy_binary(p))

                blocks.append(values)

            self.after(0, lambda b=blocks, jid=job_id: self._render_entropy(jid, b))

        except Exception as e:
            self.after(0, lambda m=f"Entropy error: {e}", jid=job_id: self._render_error(jid, m))

    def _render_entropy(self, job_id, blocks):
        if job_id != self._entropy_job_id:
            return

        self._clear_entropy_grid()

        cols = 3
        for idx, block in enumerate(blocks):
            col = idx % cols
            row = idx // cols

            frame = tk.Frame(self.entropy_grid, bg="#F9FAFB", highlightthickness=1, highlightbackground="#E5E7EB")
            frame.grid(row=row, column=col, padx=12, pady=12, sticky="n")

            tk.Label(frame, text=f"Block {idx + 1}", bg="#F9FAFB", fg="#111111", font=("Inter", 11, "bold")).pack(anchor="w", padx=12, pady=(8, 4))

            for r, H in enumerate(block):
                tk.Label(frame, text=f"R{r + 1:02d}: {H:.6f}", bg="#F9FAFB", fg="#111111", font=("Inter", 10)).pack(anchor="w", padx=12)

    def _render_error(self, job_id, text):
        if job_id != self._entropy_job_id:
            return
        self._clear_entropy_grid()
        tk.Label(self.entropy_grid, text=text, fg="red", bg="#FFFFFF", font=("Inter", 11)).pack(anchor="w")
