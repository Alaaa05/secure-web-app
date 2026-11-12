from validators import check_password

passwords = ["abc", "password123", "Password123", "Admin@123"]

for pw in passwords:
    problems = check_password(pw)
    if problems:
        print(pw, "-> rejected:", ", ".join(problems))
    else:
        print(pw, "-> accepted")