import customtkinter as ctk


ctk.set_appearance_mode("Dark")       # Dark mode
ctk.set_default_color_theme("blue")  # Accent color for buttons


app = ctk.CTk()
app.geometry("600x400")
app.title("CommUnity")


title_label = ctk.CTkLabel(app, text="CommUnity", font=("Helvetica", 18, "bold"))
title_label.pack(pady=20)


username_label = ctk.CTkLabel(app, text="Username:")
username_label.pack(pady=(5, 0))
username_entry = ctk.CTkEntry(app, width=300)
username_entry.pack(pady=5)


password_label = ctk.CTkLabel(app, text="Password:")
password_label.pack(pady=(5, 0))
password_entry = ctk.CTkEntry(app, show="*", width=200)
password_entry.pack(pady=5)

login_button = ctk.CTkButton(app, text="Login")
login_button.pack(pady=20)


app.mainloop()



































