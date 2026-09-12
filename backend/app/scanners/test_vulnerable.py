import subprocess
import pickle
import hashlib

def vulnerable_function(user_input):
    # Code injection
    result = eval(user_input)

    # Command injection
    subprocess.run(user_input, shell=True)

    # Unsafe deserialization
    data = pickle.loads(user_input)

    # Weak cryptographic hash
    password_hash = hashlib.md5(
        user_input.encode()
    ).hexdigest()

    return result, data, password_hash
