
import tkinter as tk
from tkinter import Label, Button, messagebox, Frame, simpledialog, ttk, Frame
import json
import os


root = tk.Tk()
root.configure(bg="#f0f0f0")

#Title
root.title("CommUnity")
root.geometry("400x500")

###############################################################################################



username = tk.Entry(root, width=30 ,bg="white")
username.pack(pady=10)

password = tk.Entry(root,show="*")
password.pack(pady=20)



Button = tk.Button(root,text="Login",)
Button.pack(pady=20)

Button = tk.Button(root,text="@",)
Button.pack(side=tk.LEFT, pady=20)

Button = tk.Button(root,text="Login",)
Button.pack(side=tk.RIGHT, pady=20)




root.mainloop()

