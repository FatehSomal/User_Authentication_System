import tkinter as tk
from tkinter import ttk
import mysql.connector
from datetime import datetime
import string
special_characters = '!@#$%^&*()-_+='
from Crypto.Hash import SHA256
from dotenv import load_dotenv
import os

load_dotenv()

conn = mysql.connector.connect(
    host = os.getenv("DB_HOST"),
    user = os.getenv("DB_USER"),
    password = os.getenv("DB_PASSWORD"),
    database = os.getenv("DB_NAME")
)

cursor = conn.cursor()
query1 = 'SELECT password FROM project2 WHERE username = %s;'
query2 = 'INSERT INTO project2(password, username) VALUES (%s,%s);'
query21 = 'INSERT INTO project21(password, username) VALUES (%s,%s);'
query3 = 'SELECT username FROM project2 WHERE username = %s;'
query4 = 'INSERT INTO project2_logs(username, status, timestamp) VALUES (%s,%s,%s);'
query5 = 'SELECT username, status, timestamp FROM project2_logs ORDER BY timestamp DESC;'
query6 = 'SELECT username, password From project21;'
query7 = 'SELECT COUNT(username) FROM project2;'
query8 = 'DELETE FROM project2 WHERE username = %s;'
query81 = 'DELETE FROM project21 WHERE username = %s;'
query9 = 'SELECT username FROM project2 WHERE username = %s;'
query10 = 'UPDATE project2 SET username = %s, password = %s WHERE username = %s;'
query101 = 'UPDATE project21 SET username = %s, password = %s WHERE username = %s;'

root = tk.Tk()

root.geometry('500x500')
root.title('User Authentication System')

u1 = tk.Label(root, text='UserName:', font=('Arial',14))
u1.pack(padx=10, pady=(70,10))

e1 = tk.Entry(root)
e1.pack(padx=10)

u2 = tk.Label(root, text='Password:', font=('Arial',14), )
u2.pack(padx=10, pady=(40,10))

e2 = tk.Entry(root, show='*')
e2.pack(padx=10)

output = tk.Label(root, font=('Arial', 12))
output.pack(padx=10,pady=(20,0))

def entr():
    global output
    user_input = e1.get()
    cursor.execute(query1, (user_input,))
    row = cursor.fetchone()
    p = row[0].strip() if row else None
    if p is None:
        output.config(text="User not found.")
        return
    pword = e2.get()
    if pword == p:
        rt = tk.Tk()
        rt.geometry('400x400')
        rt.title('Post Login Menu')
        lbl1 = tk.Label(rt, text='Welcome!', font=('Arial', 20))
        lbl1.pack(padx=10,pady=40)
        def bm_fn():
            user_w = tk.Toplevel(rt)
            user_w.title('User info')
            user_w.geometry('700x400')

            tree2 = ttk.Treeview(user_w,columns=('username','password'), show='headings')
            tree2.heading('username', text='Username')
            tree2.heading('password', text='Password')

            tree2.pack(expand=True, fill='both', padx=10,pady=10)

            cursor.execute(query6)
            rows2 = cursor.fetchall()

            for r2 in rows2:
                tree2.insert('', tk.END, values=r2)

            status_lbl = tk.Label(user_w, text="", font=('Arial', 10), fg='red')
            status_lbl.pack(pady=(0,10))

            def dlt():
                select = tree2.selection()
                if not select:
                    status_lbl.config(text='No user selected.')
                    return
                user_data = tree2.item(select)['values']
                username = user_data[0]

                if username == e1.get():
                    status_lbl.config(text='Cannot delete currently logged in user.')
                    return
                
                cursor.execute(query8,(username,))
                cursor.execute(query81,(username,))
                conn.commit()
                tree2.delete(select)
                status_lbl.config(text=f'User: {username} deleted successfully.')


            delt_btn = tk.Button(user_w,text='Delete Selected User',command=dlt)
            delt_btn.pack(padx=10,pady=(0,10))

            def edt():
                select = tree2.selection()
                if not select:
                    status_lbl.config(text='No user selected.')
                    return
                user_data = tree2.item(select)['values']
                old_username = user_data[0]
                if old_username == e1.get():
                    status_lbl.config(text='Cannot edit currently logged in user.')
                    return
                edit_w = tk.Toplevel(user_w)
                edit_w.geometry('300x250')
                edit_w.title('Edit Login Credentials')

                p1 = tk.Label(edit_w,text='Enter New Username:')
                p1.pack(padx=10,pady=20)

                pe1 = tk.Entry(edit_w)
                pe1.pack(padx=10)

                p2 = tk.Label(edit_w,text='Enter New Password:')
                p2.pack(padx=10,pady=20)

                pe2 = tk.Entry(edit_w,show='*')
                pe2.pack(padx=10)

                p3 = tk.Label(edit_w,text='',fg='red')
                p3.pack(padx=10,pady=10)

                def sve():
                    new_user = pe1.get().strip()
                    new_pass = pe2.get().strip()
                    np = new_pass.encode('utf-8')
                    hash_hex = SHA256.new(np).hexdigest()

                    if not new_user or not new_pass:
                        p3.config(text='Username and password cannot be empty.')
                        return
                    if new_user != old_username:
                        cursor.execute(query9,(new_user,))
                        if cursor.fetchone():
                            p3.config(text='Username already taken.')
                            return
                    
                    cursor.execute(query10, (new_user,new_pass,old_username))
                    cursor.execute(query101, (new_user,hash_hex,old_username))
                    conn.commit()

                    tree2.item(select, values=(new_user,hash_hex))

                    p3.config(text='User updated successfully.', fg='green')
                    edit_w.after(1500,edit_w.destroy)

                be1 = tk.Button(edit_w,text='Save',command=sve)
                be1.pack(padx=10,pady=10)

            edt_btn = tk.Button(user_w,text='Edit Selected User',command=edt)
            edt_btn.pack(padx=10,pady=(0,10))

        bm = tk.Button(rt, text='View Users', command=bm_fn)
        bm.pack(padx=10,pady=30)
        def bn_fn():
            log_w = tk.Toplevel(rt)
            log_w.title('Audit Log')
            log_w.geometry('700x400')

            tree = ttk.Treeview(log_w,columns=('username','status','timestamp'), show='headings')
            tree.heading('username', text='Username')
            tree.heading('status', text='Status')
            tree.heading('timestamp', text='Timestamp')

            tree.pack(expand=True, fill='both', padx=10,pady=10)

            cursor.execute(query5)
            rows = cursor.fetchall()

            for r in rows:
                tree.insert('', tk.END, values=r)

        bn = tk.Button(rt, text='View Logs', command=bn_fn)
        bn.pack(padx=10,pady=30)
        def ext():
            rt.destroy()
        xt = tk.Button(rt, text='Exit', command=ext)
        xt.pack(padx=10,pady=30)
        status = 'success'
    else:
        output.config(text='Access Denied, incorrect password.')
        status = 'fail'
    cursor.execute(query4, (user_input, status, datetime.now()))
    conn.commit()

enter = tk.Button(root, text='Enter', font=('Arial', 12), command= entr)
enter.pack(padx=10, pady=20,)

u3 = tk.Label(root, text='New User? Click yes to create your user id:', font=('Arial', 12))
u3.pack(padx=10,pady=(30,10))

def ys():
    r = tk.Tk()
    r.geometry('400x400')
    r.title('New User')
    lab1 = tk.Label(r, text='New UserName:')
    lab1.pack(padx=10,pady=20)
    ent1 = tk.Entry(r)
    ent1.pack(padx=10)
    lab2 = tk.Label(r, text='New Password:')
    lab2.pack(padx=10,pady=20)
    ent2 = tk.Entry(r, show='*')
    ent2.pack(padx=10)
    op2 = tk.Label(r)
    op2.pack(padx=10,pady=(2,0))
    lab3 = tk.Label(r, text='Re-Enter Password:')
    lab3.pack(padx=10,pady=(10,20))
    ent3 = tk.Entry(r, show='*')
    ent3.pack(padx=10)
    op = tk.Label(r)
    op.pack(padx=10,pady=10)
    def save():
        i = ent1.get()
        j = ent2.get()
        k = ent3.get()
        cursor.execute(query3, (i,))
        rw = cursor.fetchone()
        if rw:
            op.config(text='UserName already taken, select another.')
            return
        else:
            if (
                len(j) >= 8
                and any(c.isupper() for c in j)
                and any(c.isdigit() for c in j)
                and any(c in special_characters for c in j)
            ):
                op2.config(text='')
                if k == j:
                    dt = j.encode('utf-8')
                    hash_hex = SHA256.new(dt).hexdigest()
                    cursor.execute(query21, (hash_hex,i))
                    cursor.execute(query2, (j,i))
                    conn.commit()
                    op.config(text='Your UserName and password are saved successfully!!\n\nWindow closes automatically in 3 seconds.')
                    r.after(2500 ,r.destroy)
                else:
                    op.config(text='The passwords entered are not matching, Please recheck.')
            else:
                op2.config(text='Passwors is too week.\nUse at least 8 characters, 1 capital letter, 1 number and 1 special symbol.')
    er = tk.Button(r, text='Save', font=('Arial',8), command=save)
    er.pack(padx=10,pady=10)
    r.mainloop()

yes = tk.Button(root, text='Yes!', font=('Arial', 10), command=ys)
yes.pack(padx=10)

root.mainloop()