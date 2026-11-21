import db

# a username with a quote and --  inside it.
# a safe query should look for a user with exactly this name and find nobody.
test_username = "admin' --"

print("Looking up the username:", test_username, "\n")

db.SECURE_MODE = False
user = db.find_user(test_username)
if user:
    print("Vulnerable version: the input changed the query and returned", user["username"])
else:
    print("Vulnerable version: no user found")

db.SECURE_MODE = True
user = db.find_user(test_username)
if user:
    print("Fixed version: the input changed the query and returned", user["username"])
else:
    print("Fixed version: no user found, the input was treated as plain text")