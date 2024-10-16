import mysql.connector
import tkinter as tk
from tkinter import messagebox
import random
import string
import platform
import sys
'''
mydb=mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="@Ayushi10@",
    database="password_manager"
)
mycursor=mydb..cursor()

#mycursor.execute("Create Database password_manager")
mycursor.execute(
    """CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL UNIQUE
)""")
'''
'''mycursor._execute_query("""ALTER TABLE users
ADD COLUMN role ENUM('user', 'superuser') DEFAULT 'user';
""")
'''
# Function to check if the current OS is Windows
def check_os():
    current_os = platform.system()
    if current_os != "Linux":
        messagebox.showerror("Error", "This application can only run on Windows.")
        sys.exit()


# Function to generate password
def generate_password():
    length = int(length_entry.get())
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)


# Function to copy password to clipboard
def copy_password():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!")


# Function to register superuser or regular user in the database
def store_in_db(is_superuser=False):
    email = email_entry.get()
    password = password_entry.get()

    if email == "" or password == "":
        messagebox.showerror("Error", "Both Email and Password are required!")
        return

    role = 'superuser' if is_superuser else 'user'

    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@Ayushi10@",
            database="password_manager"
        )
        cursor = conn.cursor()

        # SQL query to insert email, password, and role
        query = "INSERT INTO users (email, password, role) VALUES (%s, %s, %s)"
        cursor.execute(query, (email, password, role))
        conn.commit()

        messagebox.showinfo("Success", f"{'Superuser' if is_superuser else 'User'} registered successfully!")

    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Error: {err}")


# Function to authenticate a superuser
def authenticate_superuser():
    email = email_entry.get()
    password = password_entry.get()

    if email == "" or password == "":
        messagebox.showerror("Error", "Email and Password are required for login!")
        return

    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@Ayushi10@",
            database="password_manager"
        )
        cursor = conn.cursor()

        # SQL query to check if the email and password match a superuser
        query = "SELECT role FROM users WHERE email = %s AND password = %s"
        cursor.execute(query, (email, password))
        result = cursor.fetchone()

        if result:
            if result[0] == 'superuser':
                messagebox.showinfo("Access Granted", "You are logged in as a superuser!")
                # Enable the "Retrieve User Passwords" button
                retrieve_passwords_btn.config(state=tk.NORMAL)
            else:
                messagebox.showerror("Access Denied", "You are not a superuser!")
        else:
            messagebox.showerror("Error", "Invalid email or password!")

    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Error: {err}")


# Function to retrieve and display only user passwords
def retrieve_user_passwords():
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@Ayushi10@",
            database="password_manager"
        )
        cursor = conn.cursor()

        # SQL query to retrieve passwords of all regular users (excluding superusers)
        query = "SELECT email, password FROM users WHERE role = 'user'"
        cursor.execute(query)
        results = cursor.fetchall()

        # Clear the textbox before inserting new data
        retrieve_passwords_textbox.delete(1.0, tk.END)

        # Populate the text widget with the results
        for email, password in results:
            retrieve_passwords_textbox.insert(tk.END, f"Email: {email}, Password: {password}\n")

        if not results:
            retrieve_passwords_textbox.insert(tk.END, "No user data available.")

    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Error: {err}")


# Setting up the GUI window
root = tk.Tk()
root.title("Password Generator & Registration")
root.geometry("500x500")
root.resizable(False, False)

# Check if OS is Windows
check_os()

# Label for email
email_label = tk.Label(root, text="Email:")
email_label.pack(pady=5)

# Entry for email input
email_entry = tk.Entry(root, width=50)
email_entry.pack(pady=5)

# Label for password length
length_label = tk.Label(root, text="Password Length:")
length_label.pack(pady=5)

# Entry for length input
length_entry = tk.Entry(root, width=20)
length_entry.pack(pady=5)

# Button to generate password
generate_btn = tk.Button(root, text="Generate Password", command=generate_password)
generate_btn.pack(pady=5)

# Entry to display the generated password
password_entry = tk.Entry(root, width=50)
password_entry.pack(pady=5)

# Button to copy the password
copy_btn = tk.Button(root, text="Copy Password", command=copy_password)
copy_btn.pack(pady=5)

# Button to register as a regular user
register_btn = tk.Button(root, text="Register as User", command=lambda: store_in_db(is_superuser=False))
register_btn.pack(pady=5)

# Button to register as a superuser
superuser_register_btn = tk.Button(root, text="Register as Superuser", command=lambda: store_in_db(is_superuser=True))
superuser_register_btn.pack(pady=5)

# Button to authenticate as superuser
authenticate_btn = tk.Button(root, text="Login as Superuser", command=authenticate_superuser)
authenticate_btn.pack(pady=5)

# Button to retrieve user passwords (initially disabled)
retrieve_passwords_btn = tk.Button(root, text="Retrieve User Passwords", command=retrieve_user_passwords, state=tk.DISABLED)
retrieve_passwords_btn.pack(pady=5)

# Textbox to display retrieved passwords
retrieve_passwords_textbox = tk.Text(root, height=10, width=60, state=tk.NORMAL)
retrieve_passwords_textbox.pack(pady=5)

# Mainloop to run the GUI application
root.mainloop()
