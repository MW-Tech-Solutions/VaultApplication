import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.font import Font
import mysql.connector
import pyotp
import qrcode
from PIL import Image, ImageTk
import tempfile

# MySQL Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""  # Update this to your MySQL password
DB_NAME = "vault_db"

# Initialize Database
def init_db():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        conn.database = DB_NAME
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                otp_secret VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                service VARCHAR(255) NOT NULL,
                vault_username VARCHAR(255) NOT NULL,
                vault_password VARCHAR(255) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        messagebox.showerror("Database Error", f"Failed to initialize database: {e}")
        raise

class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure Vault")
        self.geometry("800x600")
        self.resizable(False, False)
        self.current_user_id = None
        self.dark_mode = False

        # Fonts
        self.title_font = Font(family="Segoe UI", size=14, weight="bold")
        self.normal_font = Font(family="Segoe UI", size=12)

        # Style Setup
        self.style = ttk.Style()
        self.apply_theme(self.dark_mode)

        # Center Frame
        self.center_frame = ttk.Frame(self, style="Card.TFrame")
        self.center_frame.pack(expand=True, fill="both")

        # Status Bar
        self.status_bar = ttk.Label(self, text="Ready", relief="sunken")
        self.status_bar.pack(side="bottom", fill="x")

        # Initialize Frames
        self.frames = {}
        for F in (LoginFrame, RegisterFrame, VaultFrame):
            frame = F(self.center_frame, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def apply_theme(self, dark_mode):
        bg_color = "#2c2c2c" if dark_mode else "#f0f0f0"
        fg_color = "#ffffff" if dark_mode else "#000000"
        btn_bg = "#3a3a3a" if dark_mode else "#e0e0e0"
        btn_hover = "#505050" if dark_mode else "#d0d0d0"

        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", padding=6, relief="flat", background=btn_bg, foreground=fg_color)
        self.style.map("TButton", background=[("active", btn_hover)])
        self.style.configure("TEntry", padding=5, relief="flat", fieldbackground=bg_color, foreground=fg_color)
        self.configure(bg=bg_color)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme(self.dark_mode)

    def show_frame(self, page_name, user_id=None):
        for frame in self.frames.values():
            frame.grid_remove()
        frame = self.frames[page_name]
        if page_name == "VaultFrame" and user_id is not None:
            self.current_user_id = user_id
            frame.load_vault_data(user_id)
        frame.grid(row=0, column=0, sticky="nsew")
        self.update_status(f"Current Page: {page_name.replace('Frame', '')}")

    def update_status(self, message):
        self.status_bar.config(text=message)

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="Card.TFrame")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        center = ttk.Frame(self, style="Card.TFrame")
        center.pack(expand=True)

        ttk.Label(center, text="🔐 Login to Your Vault", font=self.controller.title_font, style="TLabel").pack(pady=20)

        self.username = ttk.Entry(center, width=30, font=self.controller.normal_font, style="Rounded.TEntry")
        self.username.pack(pady=(10, 5))
        self.username.insert(0, "Username")
        self.username.bind("<FocusIn>", lambda e: self.username.delete(0, 'end'))

        self.password = ttk.Entry(center, width=30, show="*", font=self.controller.normal_font, style="Rounded.TEntry")
        self.password.pack(pady=(0, 15))
        self.password.insert(0, "Password")
        self.password.bind("<FocusIn>", lambda e: self.password.delete(0, 'end'))

        ttk.Button(center, text="Login", command=self.login, width=20).pack(pady=5)
        ttk.Button(center, text="Register", command=lambda: self.controller.show_frame("RegisterFrame"), width=20).pack()

        self.status = ttk.Label(center, text="", style="TLabel")
        self.status.pack(pady=10)

    def login(self):
        username = self.username.get()
        password = self.password.get()

        if not username or not password or username == "Username" or password == "Password":
            self.status.config(text="❗ All fields required", foreground="red")
            return

        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor()
            cursor.execute("SELECT id, password, otp_secret FROM users WHERE username=%s", (username,))
            user = cursor.fetchone()
            conn.close()

            if not user or password != user[1]:
                self.status.config(text="❌ Invalid credentials", foreground="red")
                return

            user_id, stored_password, otp_secret = user
            self.controller.current_user_id = user_id
            self.otp_verification_window(otp_secret)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def otp_verification_window(self, otp_secret):
        otp_window = tk.Toplevel(self)
        otp_window.title("2FA Verification")
        otp_window.geometry("300x150")

        ttk.Label(otp_window, text="Enter the code from Google Authenticator:", style="TLabel").pack(pady=5)
        otp_entry = ttk.Entry(otp_window, width=20, font=self.controller.normal_font, style="Rounded.TEntry")
        otp_entry.pack(pady=5)

        def verify_code():
            code = otp_entry.get().strip()
            if not code.isdigit() or len(code) != 6:
                messagebox.showerror("Error", "Enter a valid 6-digit code.")
                return

            if pyotp.TOTP(otp_secret).verify(code):
                otp_window.destroy()
                self.controller.show_frame("VaultFrame", user_id=self.controller.current_user_id)
            else:
                messagebox.showerror("Error", "Invalid code.")

        ttk.Button(otp_window, text="Verify", command=verify_code, width=15).pack(pady=5)

class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="Card.TFrame")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        center = ttk.Frame(self, style="Card.TFrame")
        center.pack(expand=True)

        ttk.Label(center, text="Register New Account", font=self.controller.title_font, style="TLabel").pack(pady=20)

        self.entries = {}
        for field in ["Username", "Password", "Confirm Password"]:
            ttk.Label(center, text=field, style="TLabel").pack(pady=(5, 0))
            entry = ttk.Entry(center, width=30, show="*" if "Password" in field else "", style="Rounded.TEntry")
            entry.pack(pady=(0, 10))
            self.entries[field] = entry

        ttk.Button(center, text="Register", command=self.register, width=20).pack(pady=10)
        ttk.Button(center, text="Back to Login", command=lambda: self.controller.show_frame("LoginFrame"), width=20).pack()

        self.status = ttk.Label(center, text="", style="TLabel")
        self.status.pack(pady=10)

    def register(self):
        data = {k: v.get() for k, v in self.entries.items()}
        if any(not v for v in data.values()):
            self.status.config(text="❗ All fields required", foreground="red")
            return
        if data["Password"] != data["Confirm Password"]:
            self.status.config(text="❌ Passwords do not match", foreground="red")
            return

        otp_secret = pyotp.random_base32()

        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, otp_secret) VALUES (%s, %s, %s)",
                          (data["Username"], data["Password"], otp_secret))
            conn.commit()
            conn.close()
            self.status.config(text="✅ Registration successful!", foreground="green")
            self.generate_qr_code(data["Username"], otp_secret)
            self.controller.after(1500, lambda: self.controller.show_frame("LoginFrame"))
        except mysql.connector.IntegrityError:
            self.status.config(text="❌ Username already exists", foreground="red")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_qr_code(self, username, secret):
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureVault")
        qr = qrcode.make(uri)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            qr.save(tmp.name)
            tmp_path = tmp.name

        qr_window = tk.Toplevel(self)
        qr_window.title("Scan QR Code")
        img = Image.open(tmp_path)
        img = img.resize((200, 200), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)

        ttk.Label(qr_window, text="Scan this QR code with Google Authenticator", style="TLabel").pack()
        ttk.Label(qr_window, image=photo).pack()
        qr_window.image = photo

        ttk.Button(qr_window, text="Close", command=qr_window.destroy, width=15).pack(pady=10)

class VaultFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="Card.TFrame")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        header = ttk.Frame(self, style="Card.TFrame")
        header.pack(fill="x", padx=10, pady=10)

        ttk.Label(header, text="🔐 Vault Entries", font=self.controller.title_font, style="TLabel").pack(side="left")

        ttk.Button(header, text="➕ Add Entry", command=self.add_entry_dialog, width=15).pack(side="right")
        ttk.Button(header, text="🔒 Logout", command=self.logout, width=15).pack(side="right", padx=5)

        self.tree = ttk.Treeview(self, show="headings", selectmode="browse")
        self.tree["columns"] = ("Service", "Username", "Password")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Edit", command=self.edit_entry)
        self.context_menu.add_command(label="Delete", command=self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        try:
            self.tree.selection_set(self.tree.identify_row(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def load_vault_data(self, user_id):
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            conn = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
            cursor = conn.cursor()
            cursor.execute("SELECT service, vault_username, vault_password FROM vault WHERE user_id=%s", (user_id,))
            for row in cursor.fetchall():
                self.tree.insert("", "end", values=row)
            conn.close()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_entry_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add New Entry")
        dialog.geometry("400x250")
        dialog.transient(self)
        dialog.grab_set()

        fields = {}
        for i, field in enumerate(["Service", "Username", "Password"]):
            ttk.Label(dialog, text=field, style="TLabel").grid(row=i, column=0, padx=10, pady=5)
            entry = ttk.Entry(dialog, width=30, show="*" if field == "Password" else "", style="Rounded.TEntry")
            entry.grid(row=i, column=1, padx=10, pady=5)
            fields[field] = entry

        def save():
            values = {k: v.get() for k, v in fields.items()}
            if any(not v for v in values.values()):
                messagebox.showerror("Error", "All fields required")
                return

            try:
                conn = mysql.connector.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME
                )
                cursor = conn.cursor()
                cursor.execute("INSERT INTO vault (user_id, service, vault_username, vault_password) VALUES (%s, %s, %s, %s)",
                              (self.controller.current_user_id, values["Service"], values["Username"], values["Password"]))
                conn.commit()
                conn.close()
                self.load_vault_data(self.controller.current_user_id)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(dialog, text="Save", command=save).grid(row=3, column=0, columnspan=2, pady=10)

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            return

        values = self.tree.item(selected)['values']
        dialog = tk.Toplevel(self)
        dialog.title("Edit Entry")
        dialog.geometry("400x250")
        dialog.transient(self)
        dialog.grab_set()

        fields = {}
        for i, (field, val) in enumerate(zip(["Service", "Username", "Password"], values)):
            ttk.Label(dialog, text=field, style="TLabel").grid(row=i, column=0, padx=10, pady=5)
            entry = ttk.Entry(dialog, width=30, show="*" if field == "Password" else "", style="Rounded.TEntry")
            entry.insert(0, val)
            entry.grid(row=i, column=1, padx=10, pady=5)
            fields[field] = entry

        def update():
            new_values = {k: v.get() for k, v in fields.items()}
            try:
                conn = mysql.connector.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME
                )
                cursor = conn.cursor()
                cursor.execute("UPDATE vault SET service=%s, vault_username=%s, vault_password=%s WHERE service=%s AND user_id=%s",
                              (new_values["Service"], new_values["Username"], new_values["Password"], values[0], self.controller.current_user_id))
                conn.commit()
                conn.close()
                self.load_vault_data(self.controller.current_user_id)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(dialog, text="Update", command=update).grid(row=3, column=0, columnspan=2, pady=10)

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            return

        values = self.tree.item(selected)['values']
        if messagebox.askyesno("Confirm", "Delete selected entry?"):
            try:
                conn = mysql.connector.connect(
                    host=DB_HOST,
                    user=DB_USER,
                    password=DB_PASSWORD,
                    database=DB_NAME
                )
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vault WHERE service=%s AND user_id=%s",
                              (values[0], self.controller.current_user_id))
                conn.commit()
                conn.close()
                self.load_vault_data(self.controller.current_user_id)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def logout(self):
        self.controller.current_user_id = None
        self.controller.show_frame("LoginFrame")

if __name__ == "__main__":
    init_db()
    app = VaultApp()
    app.mainloop()