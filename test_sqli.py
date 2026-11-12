import hashlib
import db

# the attack: the  --  turns the rest of the SQL query into a comment,
# so the password check never runs
attack_username = "admin' --"
wrong_password = hashlib.md5("totally-wrong".encode()).hexdigest()

print("Trying to log in as:", attack_username)
print("with a wrong password\n")

# run the attack against the vulnerable version
db.SECURE_MODE = False
user = db.find_user(attack_username, wrong_password)
if user:
    print("Vulnerable version: logged in as", user["username"], "with role", user["role"])
else:
    print("Vulnerable version: login failed")

# run the same attack against the fixed version
db.SECURE_MODE = True
user = db.find_user(attack_username, wrong_password)
if user:
    print("Fixed version: logged in as", user["username"], "with role", user["role"])
else:
    print("Fixed version: login failed")