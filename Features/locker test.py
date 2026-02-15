
#!/usr/bin/env python3
"""
Folder Locker - simple GUI to create/unlock/lock encrypted folders on Linux.

Features:
- Preferred backend: gocryptfs (on-the-fly encryption + mount).
- Fallback: hide folder and change permissions (not cryptographically secure).
- Stores password hashes (PBKDF2 + salt) in ~/.folder_locker/config.json
- Uses xdg-open to open unlocked folder in file manager.

Usage:
- Run: python3 folder_locker.py
- Buttons: Initialize (create protected folder), Unlock (mount/open), Lock (unmount/hide)
"""

import os
import json
import subprocess
import hashlib
import secrets
import pathlib
import sys
import shutil
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog

HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME, ".folder_locker")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
MOUNT_BASE = os.path.join(CONFIG_DIR, "mounts")  # where mounts (decrypted view) appear
ENCRYPTED_BASE = os.path.join(CONFIG_DIR, "encrypted")  # where encrypted data lives

# PBKDF2 params
HASH_NAME = "sha256"
ITERATIONS = 200_000
KEYLEN = 32

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(MOUNT_BASE, exist_ok=True)
os.makedirs(ENCRYPTED_BASE, exist_ok=True)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def hash_password(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, ITERATIONS, dklen=KEYLEN).hex()

def gocryptfs_available():
    return shutil.which("gocryptfs") is not None

def run_cmd(cmd, capture=False):
    try:
        if capture:
            return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")
        else:
            subprocess.check_call(cmd)
            return ""
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="ignore") if e.output else str(e)

def ensure_trailing_dir(path):
    return os.path.abspath(path)

def create_protected_folder_gui(root):
    cfg = load_config()

    # pick real folder to protect
    real_folder = filedialog.askdirectory(title="Select folder to protect (this folder's content will be protected)")
    if not real_folder:
        return
    real_folder = ensure_trailing_dir(real_folder)
    name = os.path.basename(real_folder.rstrip("/"))

    # ask for a label (optional)
    label = simpledialog.askstring("Label (optional)", f"Label for this protected item (default: {name}):", parent=root)
    if not label:
        label = name

    # ask passcode
    pwd = simpledialog.askstring("Set passcode", f"Choose a passcode to protect '{label}'", parent=root, show="*")
    if not pwd:
        messagebox.showinfo("Cancelled", "No passcode entered.")
        return

    # generate salt & store metadata
    salt = secrets.token_bytes(16)
    pwdhash = hash_password(pwd, salt)

    # prepare storage paths
    safe_id = secrets.token_hex(8)
    enc_path = os.path.join(ENCRYPTED_BASE, safe_id)
    mount_path = os.path.join(MOUNT_BASE, safe_id)

    if gocryptfs_available():
        os.makedirs(enc_path, exist_ok=False)
        # initialize gocryptfs (it will ask for password interactively; we will pass with -passwdfile)
        # create a temporary passwdfile
        pf_path = os.path.join(CONFIG_DIR, f"pw-{safe_id}.txt")
        with open(pf_path, "w") as pf:
            pf.write(pwd + "\n")
        init_cmd = ["gocryptfs", "-init", "-passwdfile", pf_path, enc_path]
        out = run_cmd(init_cmd, capture=True)
        os.remove(pf_path)
        if "initialized filesystem" not in out and "success" not in out.lower():
            # still might be ok; but warn user
            messagebox.showwarning("gocryptfs", f"gocryptfs init output:\n{out}\nYou may need to run init manually.")
    else:
        # fallback: we will move the real folder into our encrypted base as "hidden" storage
        os.makedirs(enc_path, exist_ok=False)

    # Move existing files into encrypted storage if using fallback, otherwise just remember real folder
    if not gocryptfs_available():
        try:
            target = os.path.join(enc_path, name)
            if os.path.exists(target):
                messagebox.showerror("Error", "Target already exists in safe storage.")
                return
            shutil.move(real_folder, target)
            # create a placeholder folder path for the user where the locked folder was
            os.makedirs(real_folder, exist_ok=True)  # empty placeholder - locked
            # hide placeholder by renaming? we leave placeholder visible but we'll chmod it
            # set placeholder perms to 000
            os.chmod(real_folder, 0o000)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to move folder for fallback: {e}")
            return

    # store metadata
    cfg.setdefault("safes", {})
    cfg["safes"][safe_id] = {
        "label": label,
        "orig_path": real_folder,
        "enc_path": enc_path,
        "mount_path": mount_path,
        "salt": salt.hex(),
        "pwdhash": pwdhash,
        "backend": "gocryptfs" if gocryptfs_available() else "fallback"
    }
    save_config(cfg)
    messagebox.showinfo("Done", f"Protected folder '{label}' created.\nID: {safe_id}\nUse Unlock to open it.")

def unlock_safe_gui(root):
    cfg = load_config()
    safes = cfg.get("safes", {})
    if not safes:
        messagebox.showinfo("No safes", "No protected folders set up yet. Use Initialize.")
        return

    # Ask user to pick which safe (simple chooser)
    choices = [f"{sid} — {safes[sid]['label']}" for sid in safes]
    choice = simpledialog.askstring("Choose safe", "Enter safe ID or label:\n" + "\n".join(choices), parent=root)
    if not choice:
        return

    # attempt to match id or label
    chosen_id = None
    for sid, meta in safes.items():
        if choice == sid or choice == meta["label"]:
            chosen_id = sid
            break
    if not chosen_id:
        # try partial match by id start
        for sid in safes:
            if sid.startswith(choice):
                chosen_id = sid
                break
    if not chosen_id:
        messagebox.showerror("Not found", "No matching safe found.")
        return

    meta = safes[chosen_id]
    pwd = simpledialog.askstring("Passcode", f"Enter passcode for '{meta['label']}'", parent=root, show="*")
    if not pwd:
        return

    salt = bytes.fromhex(meta["salt"])
    if hash_password(pwd, salt) != meta["pwdhash"]:
        messagebox.showerror("Wrong", "Passcode is incorrect.")
        return

    # correct passcode — unlock depending on backend
    if meta["backend"] == "gocryptfs":
        enc_path = meta["enc_path"]
        mount_path = meta["mount_path"]
        os.makedirs(mount_path, exist_ok=True)
        # create passwd file
        pf = os.path.join(CONFIG_DIR, f"pw-unlock-{chosen_id}.txt")
        with open(pf, "w") as f:
            f.write(pwd + "\n")
        # mount (gocryptfs -passwdfile enc_path mount_path)
        cmd = ["gocryptfs", "-passwdfile", pf, enc_path, mount_path]
        out = run_cmd(cmd, capture=True)
        try:
            os.remove(pf)
        except:
            pass
        if "Mounted" in out or "mountpoint" in out or os.path.ismount(mount_path):
            # open folder in file manager
            subprocess.Popen(["xdg-open", mount_path])
            messagebox.showinfo("Unlocked", f"Folder mounted at: {mount_path}\nIt opened in your file manager.")
        else:
            # sometimes gocryptfs prints nothing but the mount is ok — check
            if os.path.ismount(mount_path):
                subprocess.Popen(["xdg-open", mount_path])
                messagebox.showinfo("Unlocked", f"Folder mounted at: {mount_path}\nIt opened in your file manager.")
            else:
                messagebox.showerror("Mount failed", f"gocryptfs mount output:\n{out}")

    else:
        # fallback: reveal files (they were moved to enc_path/<name>), and chmod placeholder to 700 and open orig_path
        orig = meta["orig_path"]
        enc_path = meta["enc_path"]
        # find moved content inside enc_path
        items = os.listdir(enc_path)
        if not items:
            messagebox.showerror("Empty", "No content found in fallback storage.")
            return
        # restore placeholder perms so user can access
        try:
            os.chmod(orig, 0o700)
            # open the orig path (which either contains moved content or the original if not moved)
            subprocess.Popen(["xdg-open", orig])
            messagebox.showinfo("Unlocked", f"Folder unlocked and opened: {orig}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock: {e}")

def lock_safe_gui(root):
    cfg = load_config()
    safes = cfg.get("safes", {})
    if not safes:
        messagebox.showinfo("No safes", "No protected folders set up yet.")
        return

    choices = [f"{sid} — {safes[sid]['label']}" for sid in safes]
    choice = simpledialog.askstring("Choose safe to lock", "Enter safe ID or label:\n" + "\n".join(choices), parent=root)
    if not choice:
        return

    chosen_id = None
    for sid, meta in safes.items():
        if choice == sid or choice == meta["label"]:
            chosen_id = sid
            break
    if not chosen_id:
        for sid in safes:
            if sid.startswith(choice):
                chosen_id = sid
                break
    if not chosen_id:
        messagebox.showerror("Not found", "No matching safe found.")
        return

    meta = safes[chosen_id]
    if meta["backend"] == "gocryptfs":
        mount_path = meta["mount_path"]
        # unmount
        if os.path.ismount(mount_path):
            out = run_cmd(["fusermount", "-u", mount_path], capture=True)
            # if still mounted try umount
            if os.path.ismount(mount_path):
                out = run_cmd(["umount", mount_path], capture=True)
            messagebox.showinfo("Locked", f"Attempted unmount. Output:\n{out}")
        else:
            messagebox.showinfo("Already locked", "Mount not active.")
    else:
        # fallback: set permissions to 000 and ensure files are not accessible from orig_path
        orig = meta["orig_path"]
        try:
            os.chmod(orig, 0o000)
            messagebox.showinfo("Locked", f"Folder permissions changed to 000 for: {orig}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock: {e}")

def show_help():
    messagebox.showinfo("Help / Notes",
                        "This app prefers gocryptfs (install it for real encryption).\n\n"
                        "If gocryptfs is absent, the app uses a hide+chmod fallback (convenience only).\n\n"
                        "To install gocryptfs on Debian/Ubuntu/Mint:\n\n"
                        "  sudo apt update && sudo apt install gocryptfs\n\n"
                        "After initializing a safe, use Unlock to open (it will prompt for passcode).\nUse Lock to unmount/hide again.")

def build_gui():
    root = tk.Tk()
    root.title("Folder Locker")
    root.geometry("420x240")
    frm = tk.Frame(root, padx=12, pady=12)
    frm.pack(fill=tk.BOTH, expand=True)

    lbl = tk.Label(frm, text="Folder Locker — initialize a protected folder, then Unlock/Lock it", wraplength=380)
    lbl.pack(pady=(0,10))

    btn_init = tk.Button(frm, text="Initialize (create protected folder)", width=40, command=lambda: create_protected_folder_gui(root))
    btn_init.pack(pady=6)

    btn_unlock = tk.Button(frm, text="Unlock (enter passcode to open)", width=40, command=lambda: unlock_safe_gui(root))
    btn_unlock.pack(pady=6)

    btn_lock = tk.Button(frm, text="Lock (lock / unmount)", width=40, command=lambda: lock_safe_gui(root))
    btn_lock.pack(pady=6)

    btn_help = tk.Button(frm, text="Help / Install gocryptfs", command=show_help)
    btn_help.pack(side=tk.LEFT, pady=8)

    btn_quit = tk.Button(frm, text="Quit", command=root.destroy)
    btn_quit.pack(side=tk.RIGHT, pady=8)

    root.mainloop()

if __name__ == "__main__":
    build_gui()

