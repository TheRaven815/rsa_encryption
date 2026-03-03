"""
RSA Encryption Tool - Premium GUI Application
=============================================
Features:
  - RSA key pair generation (1024 / 2048 / 4096 bit)
  - OAEP-SHA256 message encryption & decryption
  - PEM key export (public + private separately)
  - PEM key import
  - Key fingerprint & metadata display
  - Copy-to-clipboard helpers
  - Animated status bar
  - Full dark-mode premium design (no external image deps)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, base64, hashlib, os, datetime

# ── Cryptography library (pip install cryptography) ──────────────────────────
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────────────────────────────────────
BG        = "#0D0F14"
PANEL     = "#13161E"
CARD      = "#1A1E2A"
BORDER    = "#252A3A"
ACCENT    = "#4F6EF7"
ACCENT2   = "#7C3AED"
SUCCESS   = "#22C55E"
ERROR     = "#EF4444"
WARNING   = "#F59E0B"
TEXT_PRI  = "#F0F2FF"
TEXT_SEC  = "#8891A8"
TEXT_DIM  = "#4B5268"
MONO      = "Consolas"
SANS      = "Segoe UI"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def fingerprint(pub_key_pem: bytes) -> str:
    digest = hashlib.sha256(pub_key_pem).digest()
    hex_fp = digest.hex()
    return ":".join(hex_fp[i:i+2] for i in range(0, 32, 2))


def styled_button(parent, text, command, accent=True, small=False, **kw):
    bg   = ACCENT  if accent else CARD
    fg   = TEXT_PRI
    font = (SANS, 9 if small else 10, "bold")
    pad  = (8, 4) if small else (14, 8)
    btn  = tk.Button(parent, text=text, command=command,
                     bg=bg, fg=fg, activebackground=ACCENT2,
                     activeforeground=TEXT_PRI, relief="flat",
                     font=font, padx=pad[0], pady=pad[1],
                     cursor="hand2", bd=0, **kw)
    btn.bind("<Enter>", lambda e: btn.config(bg=ACCENT2 if accent else BORDER))
    btn.bind("<Leave>", lambda e: btn.config(bg=bg))
    return btn


def section_label(parent, text):
    frm = tk.Frame(parent, bg=PANEL)
    frm.pack(fill="x", pady=(18, 6), padx=20)
    tk.Label(frm, text="▌ " + text, bg=PANEL, fg=ACCENT,
             font=(SANS, 11, "bold")).pack(side="left")
    tk.Frame(frm, bg=BORDER, height=1).pack(side="left", fill="x",
                                             expand=True, padx=(10, 0))


def mono_text(parent, height=6, readonly=False):
    frm  = tk.Frame(parent, bg=BORDER, bd=0, highlightthickness=0)
    scroll = tk.Scrollbar(frm, bg=CARD, troughcolor=PANEL,
                          activebackground=ACCENT, width=10)
    txt  = tk.Text(frm, height=height, bg=CARD, fg=TEXT_PRI,
                   font=(MONO, 9), insertbackground=ACCENT,
                   relief="flat", bd=8, wrap="word",
                   yscrollcommand=scroll.set,
                   state="disabled" if readonly else "normal",
                   selectbackground=ACCENT, selectforeground=TEXT_PRI)
    scroll.config(command=txt.yview)
    txt.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    frm.pack(fill="both", expand=True, padx=20, pady=4)
    return txt, frm


def set_text(txt_widget, content, readonly=True):
    state_before = txt_widget.cget("state")
    txt_widget.config(state="normal")
    txt_widget.delete("1.0", "end")
    txt_widget.insert("1.0", content)
    if readonly:
        txt_widget.config(state="disabled")
    else:
        txt_widget.config(state=state_before if state_before != "disabled" else "normal")


def get_text(txt_widget) -> str:
    return txt_widget.get("1.0", "end").strip()


def copy_to_clip(root, text):
    root.clipboard_clear()
    root.clipboard_append(text)


# ─────────────────────────────────────────────────────────────────────────────
# RSA CORE
# ─────────────────────────────────────────────────────────────────────────────
class RSACore:
    def __init__(self):
        self.private_key = None
        self.public_key  = None

    @property
    def has_private(self): return self.private_key is not None
    @property
    def has_public(self):  return self.public_key  is not None

    def generate(self, bits: int):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    # ── Export ────────────────────────────────────────────────────────────────
    def export_private_pem(self, password: bytes | None = None) -> bytes:
        enc = (serialization.BestAvailableEncryption(password)
               if password else serialization.NoEncryption())
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            enc
        )

    def export_public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # ── Import ────────────────────────────────────────────────────────────────
    def load_private_pem(self, data: bytes, password: bytes | None = None):
        self.private_key = serialization.load_pem_private_key(
            data, password=password, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def load_public_pem(self, data: bytes):
        self.public_key = serialization.load_pem_public_key(
            data, backend=default_backend()
        )

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────
    def encrypt(self, plaintext: str) -> str:
        raw = plaintext.encode("utf-8")
        # For long messages chunk & encrypt each block
        key_len   = self.public_key.key_size // 8
        max_chunk = key_len - 2 * hashes.SHA256.digest_size - 2  # OAEP overhead
        # SHA256 digest_size = 32
        max_chunk = key_len - 66
        chunks, i = [], 0
        while i < len(raw):
            chunk = raw[i:i + max_chunk]
            enc   = self.public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            chunks.append(enc)
            i += max_chunk
        # Encode: prefix with 4-byte count, then length-prefixed blocks
        result = len(chunks).to_bytes(4, "big")
        for c in chunks:
            result += len(c).to_bytes(4, "big") + c
        return base64.b64encode(result).decode("ascii")

    def decrypt(self, ciphertext_b64: str) -> str:
        data   = base64.b64decode(ciphertext_b64.encode("ascii"))
        count  = int.from_bytes(data[:4], "big")
        pos    = 4
        chunks = []
        for _ in range(count):
            length = int.from_bytes(data[pos:pos+4], "big")
            pos   += 4
            block  = data[pos:pos+length]
            pos   += length
            plain  = self.private_key.decrypt(
                block,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            chunks.append(plain)
        return b"".join(chunks).decode("utf-8")

    # ── Key info ──────────────────────────────────────────────────────────────
    def key_info(self) -> dict:
        if not self.has_public:
            return {}
        pub_pem = self.export_public_pem()
        pub_num = self.public_key.public_numbers()
        info = {
            "Key Size"  : f"{self.public_key.key_size} bits",
            "Exponent"  : str(pub_num.e),
            "Modulus"   : hex(pub_num.n)[:48] + "…",
            "Fingerprint (SHA-256)": fingerprint(pub_pem),
            "Has Private Key": "Yes ✓" if self.has_private else "No (public only)",
        }
        return info


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.core   = RSACore()
        self.title("RSA Encryption Tool")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(bg=BG)
        self._status_after = None

        self._build_header()
        self._build_notebook()
        self._build_statusbar()
        self.set_status("Ready — generate or import keys to begin.", "info")

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=PANEL, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🔐", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI Emoji", 22)).pack(side="left", padx=(20, 8), pady=10)
        tk.Label(hdr, text="RSA Encryption Tool",
                 bg=PANEL, fg=TEXT_PRI, font=(SANS, 17, "bold")).pack(side="left")
        tk.Label(hdr, text="  OAEP-SHA256 · PEM Import/Export · Multi-chunk",
                 bg=PANEL, fg=TEXT_DIM, font=(SANS, 9)).pack(side="left", padx=8)

        # Key status badge
        self._key_badge_var = tk.StringVar(value="No Keys Loaded")
        self._key_badge_lbl = tk.Label(hdr, textvariable=self._key_badge_var,
                                       bg=WARNING, fg="#0D0F14",
                                       font=(SANS, 9, "bold"),
                                       padx=10, pady=4, relief="flat")
        self._key_badge_lbl.pack(side="right", padx=20)

    # ── Notebook / Tabs ───────────────────────────────────────────────────────
    def _build_notebook(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Dark.TNotebook", background=BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                        background=PANEL, foreground=TEXT_SEC,
                        font=(SANS, 10, "bold"),
                        padding=(20, 10), borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(self, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        # Tabs
        self._tab_keys   = self._make_tab(nb, "  🔑 Key Management  ")
        self._tab_enc    = self._make_tab(nb, "  🔒 Encrypt  ")
        self._tab_dec    = self._make_tab(nb, "  🔓 Decrypt  ")
        self._tab_info   = self._make_tab(nb, "  ℹ️ Key Info  ")

        nb.add(self._tab_keys, text="  🔑 Key Management  ")
        nb.add(self._tab_enc,  text="  🔒 Encrypt  ")
        nb.add(self._tab_dec,  text="  🔓 Decrypt  ")
        nb.add(self._tab_info, text="  ℹ️ Key Info  ")

        self._build_keys_tab()
        self._build_enc_tab()
        self._build_dec_tab()
        self._build_info_tab()

    def _make_tab(self, parent, _name):
        frm = tk.Frame(parent, bg=PANEL)
        return frm

    # ─────────────────────────── KEY MANAGEMENT TAB ───────────────────────────
    def _build_keys_tab(self):
        tab = self._tab_keys

        # ── Generate ──────────────────────────────────────────────────────────
        section_label(tab, "Generate New RSA Key Pair")
        gen_frm = tk.Frame(tab, bg=PANEL)
        gen_frm.pack(fill="x", padx=20, pady=4)

        tk.Label(gen_frm, text="Key Size:", bg=PANEL, fg=TEXT_SEC,
                 font=(SANS, 10)).pack(side="left")
        self._bits_var = tk.StringVar(value="2048")
        for bits in ["1024", "2048", "4096"]:
            tk.Radiobutton(gen_frm, text=f"{bits}-bit", variable=self._bits_var,
                           value=bits, bg=PANEL, fg=TEXT_PRI,
                           selectcolor=CARD, activebackground=PANEL,
                           activeforeground=ACCENT,
                           font=(SANS, 10)).pack(side="left", padx=12)

        # Password protection
        pw_frm = tk.Frame(tab, bg=PANEL)
        pw_frm.pack(fill="x", padx=20, pady=(8, 4))
        tk.Label(pw_frm, text="Private Key Password (optional):",
                 bg=PANEL, fg=TEXT_SEC, font=(SANS, 10)).pack(side="left")
        self._pw_var = tk.StringVar()
        pw_entry = tk.Entry(pw_frm, textvariable=self._pw_var, show="●",
                            bg=CARD, fg=TEXT_PRI, insertbackground=ACCENT,
                            font=(MONO, 10), relief="flat", width=30, bd=6)
        pw_entry.pack(side="left", padx=10)
        tk.Label(pw_frm, text="(leave blank = no encryption)",
                 bg=PANEL, fg=TEXT_DIM, font=(SANS, 9)).pack(side="left")

        gen_btn_frm = tk.Frame(tab, bg=PANEL)
        gen_btn_frm.pack(fill="x", padx=20, pady=8)
        self._gen_btn = styled_button(gen_btn_frm, "⚙  Generate Key Pair",
                                      self._generate_keys)
        self._gen_btn.pack(side="left")
        self._gen_spinner = tk.Label(gen_btn_frm, text="", bg=PANEL, fg=ACCENT,
                                     font=(SANS, 10))
        self._gen_spinner.pack(side="left", padx=10)

        # ── Export ────────────────────────────────────────────────────────────
        section_label(tab, "Export Keys")
        exp_frm = tk.Frame(tab, bg=PANEL)
        exp_frm.pack(fill="x", padx=20, pady=4)
        styled_button(exp_frm, "💾  Export Public Key (.pem)",
                      self._export_public, accent=False).pack(side="left", padx=(0,8))
        styled_button(exp_frm, "💾  Export Private Key (.pem)",
                      self._export_private, accent=False).pack(side="left", padx=(0,8))
        styled_button(exp_frm, "📋  Copy Public Key",
                      self._copy_public, accent=False, small=True).pack(side="left", padx=(0,8))
        styled_button(exp_frm, "📋  Copy Private Key",
                      self._copy_private, accent=False, small=True).pack(side="left")

        # ── Import ────────────────────────────────────────────────────────────
        section_label(tab, "Import Keys")
        imp_frm = tk.Frame(tab, bg=PANEL)
        imp_frm.pack(fill="x", padx=20, pady=4)
        styled_button(imp_frm, "📂  Import Public Key",
                      self._import_public, accent=False).pack(side="left", padx=(0,8))
        styled_button(imp_frm, "📂  Import Private Key",
                      self._import_private, accent=False).pack(side="left", padx=(0,8))
        styled_button(imp_frm, "✏  Paste & Load Public Key",
                      self._paste_public, accent=False, small=True).pack(side="left", padx=(0,8))
        styled_button(imp_frm, "✏  Paste & Load Private Key",
                      self._paste_private, accent=False, small=True).pack(side="left")

        # ── Key Preview ───────────────────────────────────────────────────────
        section_label(tab, "Key Preview")
        self._key_preview, _ = mono_text(tab, height=10, readonly=True)

    # ──────────────────────────── ENCRYPT TAB ────────────────────────────────
    def _build_enc_tab(self):
        tab = self._tab_enc

        section_label(tab, "Plaintext Message")
        self._plain_txt, _ = mono_text(tab, height=8)

        btn_frm = tk.Frame(tab, bg=PANEL)
        btn_frm.pack(fill="x", padx=20, pady=8)
        styled_button(btn_frm, "🔒  Encrypt Message", self._encrypt).pack(side="left")
        styled_button(btn_frm, "🧹  Clear All", self._clear_enc,
                      accent=False, small=True).pack(side="left", padx=8)
        styled_button(btn_frm, "📋  Copy Ciphertext", self._copy_cipher,
                      accent=False, small=True).pack(side="left")

        section_label(tab, "Ciphertext (Base-64 Encoded)")
        self._cipher_txt, _ = mono_text(tab, height=8, readonly=True)

    # ──────────────────────────── DECRYPT TAB ────────────────────────────────
    def _build_dec_tab(self):
        tab = self._tab_dec

        section_label(tab, "Ciphertext (Base-64 Encoded)")
        self._dec_cipher_txt, _ = mono_text(tab, height=8)

        btn_frm = tk.Frame(tab, bg=PANEL)
        btn_frm.pack(fill="x", padx=20, pady=8)
        styled_button(btn_frm, "🔓  Decrypt Message", self._decrypt).pack(side="left")
        styled_button(btn_frm, "🧹  Clear All", self._clear_dec,
                      accent=False, small=True).pack(side="left", padx=8)
        styled_button(btn_frm, "📋  Copy Plaintext", self._copy_plain,
                      accent=False, small=True).pack(side="left")

        section_label(tab, "Decrypted Plaintext")
        self._dec_plain_txt, _ = mono_text(tab, height=8, readonly=True)

    # ──────────────────────────── INFO TAB ───────────────────────────────────
    def _build_info_tab(self):
        tab = self._tab_info

        section_label(tab, "Current Key Information")
        self._info_frame = tk.Frame(tab, bg=PANEL)
        self._info_frame.pack(fill="x", padx=20, pady=8)

        btn_frm = tk.Frame(tab, bg=PANEL)
        btn_frm.pack(fill="x", padx=20, pady=4)
        styled_button(btn_frm, "🔄  Refresh Info", self._refresh_info,
                      accent=False).pack(side="left")

        self._info_rows = {}
        labels = ["Key Size", "Exponent", "Modulus", "Fingerprint (SHA-256)", "Has Private Key"]
        for lbl in labels:
            row = tk.Frame(self._info_frame, bg=CARD, pady=8, padx=12)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl, bg=CARD, fg=TEXT_SEC,
                     font=(SANS, 9, "bold"), width=22,
                     anchor="w").pack(side="left")
            val_lbl = tk.Label(row, text="—", bg=CARD, fg=TEXT_PRI,
                               font=(MONO, 9), anchor="w")
            val_lbl.pack(side="left", fill="x", expand=True)
            self._info_rows[lbl] = val_lbl

        section_label(tab, "Public Key PEM")
        self._pub_pem_txt, _ = mono_text(tab, height=7, readonly=True)

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=CARD, height=30)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(value="")
        self._status_dot = tk.Label(bar, text="●", bg=CARD, fg=TEXT_DIM,
                                    font=(SANS, 10))
        self._status_dot.pack(side="left", padx=(12, 4))
        tk.Label(bar, textvariable=self._status_var, bg=CARD, fg=TEXT_SEC,
                 font=(SANS, 9)).pack(side="left")
        tk.Label(bar, text=f"Python RSA Tool  ·  OAEP-SHA256  ·  {datetime.date.today().year}",
                 bg=CARD, fg=TEXT_DIM, font=(SANS, 8)).pack(side="right", padx=12)

    def set_status(self, msg, kind="info"):
        colours = {"info": ACCENT, "ok": SUCCESS, "error": ERROR, "warn": WARNING}
        self._status_var.set(msg)
        self._status_dot.config(fg=colours.get(kind, ACCENT))

    # ── Key badge ─────────────────────────────────────────────────────────────
    def _update_badge(self):
        if self.core.has_private:
            txt, bg = "🔐 Key Pair Loaded", SUCCESS
        elif self.core.has_public:
            txt, bg = "🔑 Public Key Only", WARNING
        else:
            txt, bg = "No Keys Loaded", ERROR
        self._key_badge_var.set(txt)
        self._key_badge_lbl.config(bg=bg)

    # ─────────────────────────── GENERATE ────────────────────────────────────
    def _generate_keys(self):
        bits = int(self._bits_var.get())
        self._gen_btn.config(state="disabled")
        self._gen_spinner.config(text="⏳ Generating…")
        self.set_status(f"Generating {bits}-bit RSA key pair…", "info")

        def _work():
            pw  = self._pw_var.get().encode() if self._pw_var.get() else None
            self.core.generate(bits)
            pub = self.core.export_public_pem().decode()
            prv = self.core.export_private_pem(pw).decode()
            preview = f"{'─'*60}\nPUBLIC KEY\n{'─'*60}\n{pub}\n{'─'*60}\nPRIVATE KEY\n{'─'*60}\n{prv}"
            self.after(0, lambda: self._gen_done(preview))

        threading.Thread(target=_work, daemon=True).start()

    def _gen_done(self, preview):
        set_text(self._key_preview, preview)
        self._gen_btn.config(state="normal")
        self._gen_spinner.config(text="✓ Done!")
        self.after(2000, lambda: self._gen_spinner.config(text=""))
        self.set_status(f"✓  {self._bits_var.get()}-bit key pair generated successfully.", "ok")
        self._update_badge()
        self._refresh_info()

    # ─────────────────────────── EXPORT ──────────────────────────────────────
    def _export_public(self):
        if not self.core.has_public:
            return messagebox.showwarning("No Public Key", "Generate or import keys first.")
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                            filetypes=[("PEM files","*.pem"),("All","*.*")],
                                            initialfile="public_key.pem",
                                            title="Export Public Key")
        if not path: return
        with open(path, "wb") as f:
            f.write(self.core.export_public_pem())
        self.set_status(f"✓  Public key exported → {path}", "ok")

    def _export_private(self):
        if not self.core.has_private:
            return messagebox.showwarning("No Private Key", "Generate or import a private key first.")
        pw = self._pw_var.get().encode() if self._pw_var.get() else None
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                            filetypes=[("PEM files","*.pem"),("All","*.*")],
                                            initialfile="private_key.pem",
                                            title="Export Private Key")
        if not path: return
        with open(path, "wb") as f:
            f.write(self.core.export_private_pem(pw))
        self.set_status(f"✓  Private key exported → {path}", "ok")

    def _copy_public(self):
        if not self.core.has_public:
            return messagebox.showwarning("No Key", "No public key available.")
        copy_to_clip(self, self.core.export_public_pem().decode())
        self.set_status("✓  Public key copied to clipboard.", "ok")

    def _copy_private(self):
        if not self.core.has_private:
            return messagebox.showwarning("No Key", "No private key available.")
        pw = self._pw_var.get().encode() if self._pw_var.get() else None
        copy_to_clip(self, self.core.export_private_pem(pw).decode())
        self.set_status("✓  Private key copied to clipboard.", "ok")

    # ─────────────────────────── IMPORT ──────────────────────────────────────
    def _import_public(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All","*.*")],
                                          title="Import Public Key")
        if not path: return
        try:
            with open(path, "rb") as f:
                self.core.load_public_pem(f.read())
            self.set_status(f"✓  Public key imported from {path}", "ok")
            self._update_badge(); self._refresh_info()
        except Exception as e:
            messagebox.showerror("Import Error", str(e))
            self.set_status(f"✗  Import failed: {e}", "error")

    def _import_private(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All","*.*")],
                                          title="Import Private Key")
        if not path: return
        pw = self._prompt_password("Enter private key password (blank if none):")
        try:
            with open(path, "rb") as f:
                self.core.load_private_pem(f.read(), pw)
            self.set_status(f"✓  Private key imported from {path}", "ok")
            self._update_badge(); self._refresh_info()
        except Exception as e:
            messagebox.showerror("Import Error", str(e))
            self.set_status(f"✗  Import failed: {e}", "error")

    def _paste_public(self):
        dlg = PasteDialog(self, "Paste Public Key PEM", "PUBLIC KEY")
        if dlg.result:
            try:
                self.core.load_public_pem(dlg.result.encode())
                self.set_status("✓  Public key loaded from clipboard.", "ok")
                self._update_badge(); self._refresh_info()
            except Exception as e:
                messagebox.showerror("Parse Error", str(e))

    def _paste_private(self):
        dlg = PasteDialog(self, "Paste Private Key PEM", "PRIVATE KEY")
        if dlg.result:
            pw = self._prompt_password("Enter private key password (blank if none):")
            try:
                self.core.load_private_pem(dlg.result.encode(), pw)
                self.set_status("✓  Private key loaded from clipboard.", "ok")
                self._update_badge(); self._refresh_info()
            except Exception as e:
                messagebox.showerror("Parse Error", str(e))

    def _prompt_password(self, msg):
        dlg = PasswordDialog(self, msg)
        return dlg.result.encode() if dlg.result else None

    # ─────────────────────────── ENCRYPT ─────────────────────────────────────
    def _encrypt(self):
        if not self.core.has_public:
            return messagebox.showwarning("No Public Key", "Load a public key first.")
        plain = get_text(self._plain_txt)
        if not plain:
            return messagebox.showwarning("Empty", "Enter a message to encrypt.")
        try:
            ct = self.core.encrypt(plain)
            set_text(self._cipher_txt, ct)
            self.set_status(f"✓  Message encrypted ({len(plain)} chars → {len(ct)} chars ciphertext).", "ok")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.set_status(f"✗  Encryption failed: {e}", "error")

    def _clear_enc(self):
        self._plain_txt.config(state="normal")
        self._plain_txt.delete("1.0","end")
        set_text(self._cipher_txt, "")

    def _copy_cipher(self):
        ct = get_text(self._cipher_txt)
        if ct: copy_to_clip(self, ct); self.set_status("✓  Ciphertext copied.", "ok")

    # ─────────────────────────── DECRYPT ─────────────────────────────────────
    def _decrypt(self):
        if not self.core.has_private:
            return messagebox.showwarning("No Private Key", "Load a private key first.")
        ct = get_text(self._dec_cipher_txt)
        if not ct:
            return messagebox.showwarning("Empty", "Enter ciphertext to decrypt.")
        try:
            plain = self.core.decrypt(ct)
            set_text(self._dec_plain_txt, plain)
            self.set_status(f"✓  Message decrypted successfully ({len(plain)} chars).", "ok")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.set_status(f"✗  Decryption failed: {e}", "error")

    def _clear_dec(self):
        self._dec_cipher_txt.config(state="normal")
        self._dec_cipher_txt.delete("1.0","end")
        set_text(self._dec_plain_txt, "")

    def _copy_plain(self):
        plain = get_text(self._dec_plain_txt)
        if plain: copy_to_clip(self, plain); self.set_status("✓  Plaintext copied.", "ok")

    # ─────────────────────────── INFO ─────────────────────────────────────────
    def _refresh_info(self):
        info = self.core.key_info()
        for k, lbl in self._info_rows.items():
            lbl.config(text=info.get(k, "—"))
        if self.core.has_public:
            set_text(self._pub_pem_txt, self.core.export_public_pem().decode())
        else:
            set_text(self._pub_pem_txt, "No public key loaded.")


# ─────────────────────────────────────────────────────────────────────────────
# DIALOG HELPERS
# ─────────────────────────────────────────────────────────────────────────────
class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, message):
        super().__init__(parent)
        self.result = None
        self.title("Password"); self.resizable(False, False)
        self.configure(bg=PANEL)
        self.grab_set()
        tk.Label(self, text=message, bg=PANEL, fg=TEXT_PRI,
                 font=(SANS, 10), wraplength=340).pack(padx=20, pady=(16,8))
        self._var = tk.StringVar()
        e = tk.Entry(self, textvariable=self._var, show="●",
                     bg=CARD, fg=TEXT_PRI, insertbackground=ACCENT,
                     font=(MONO, 11), relief="flat", bd=8, width=32)
        e.pack(padx=20, pady=4); e.focus()
        frm = tk.Frame(self, bg=PANEL)
        frm.pack(pady=12)
        styled_button(frm, "OK", self._ok).pack(side="left", padx=4)
        styled_button(frm, "Cancel", self.destroy, accent=False).pack(side="left", padx=4)
        self.bind("<Return>", lambda _: self._ok())
        self.bind("<Escape>", lambda _: self.destroy())
        self.wait_window()

    def _ok(self):
        self.result = self._var.get()
        self.destroy()


class PasteDialog(tk.Toplevel):
    def __init__(self, parent, title, hint):
        super().__init__(parent)
        self.result = None
        self.title(title); self.resizable(True, True)
        self.geometry("640x420")
        self.configure(bg=PANEL)
        self.grab_set()
        tk.Label(self, text=f"Paste your {hint} PEM content below:",
                 bg=PANEL, fg=TEXT_PRI, font=(SANS, 10)).pack(padx=20, pady=(14,6), anchor="w")
        frm = tk.Frame(self, bg=BORDER)
        frm.pack(fill="both", expand=True, padx=20, pady=4)
        self._txt = tk.Text(frm, bg=CARD, fg=TEXT_PRI, font=(MONO, 9),
                            insertbackground=ACCENT, relief="flat", bd=8, wrap="none")
        sb = tk.Scrollbar(frm, command=self._txt.yview)
        self._txt.config(yscrollcommand=sb.set)
        self._txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        btn_frm = tk.Frame(self, bg=PANEL)
        btn_frm.pack(pady=10)
        styled_button(btn_frm, "✓  Load Key", self._ok).pack(side="left", padx=6)
        styled_button(btn_frm, "Cancel", self.destroy, accent=False).pack(side="left", padx=6)
        self.bind("<Escape>", lambda _: self.destroy())
        self.wait_window()

    def _ok(self):
        self.result = self._txt.get("1.0","end").strip()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = RSAApp()
    app.mainloop()
