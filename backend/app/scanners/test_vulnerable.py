import subprocess
import pickle
import hashlib


def vulnerable_function(user_input):
    result = eval(user_input)

    subprocess.run(
        user_input,
        shell=True
    )

    data = pickle.loads(user_input)

    password_hash = hashlib.md5(
        user_input.encode()
    ).hexdigest()

    return result, data, password_hash