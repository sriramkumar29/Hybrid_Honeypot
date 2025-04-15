import random
import pandas as pd

# Sample components to build usernames and passwords
first_names = ["john", "jane", "michael", "alice", "bob", "linda", "charlie", "david", "emma", "ryan"]
last_names = ["smith", "doe", "brown", "wilson", "taylor", "anderson", "jackson", "thomas", "lee", "martin"]
passwords = ["123", "1234", "pass", "qwerty", "password", "admin", "letmein", "secure", "abc", "7890"]

def generate_login_pairs(n=1000):
    logins = []
    for _ in range(n):
        username = random.choice(first_names) + str(random.randint(1, 999)) + random.choice(last_names)
        password = random.choice(passwords) + str(random.randint(0, 9999))
        login_pair = f"{username} {password}"
        logins.append((username, password, login_pair))
    return logins

# Generate 1000 normal login pairs
normal_logins = generate_login_pairs(1000)

# Save to TXT (just the login_pair string)
with open("normal_login_data.txt", "w") as f:
    for _, _, login in normal_logins:
        f.write(login + "\n")

# Save to CSV with structured columns
df = pd.DataFrame(normal_logins, columns=["username", "password", "login_pair"])
df.to_csv("normal_login_data.csv", index=False)

print("Normal login dataset saved as 'normal_login_data.txt' and 'normal_login_data.csv'")
