import os
import platform
def generate_key_with_dev_random(length):
    """
    Generate a cryptographically secure key using /dev/random
    on Unix
    or an equivalent source on Windows.
    :param length: Length of the key in bytes.
    :return: Randomly generated key as bytes.
    """
    if platform.system() == 'Windows':
    # Use os.urandom (which relies on CryptGenRandom on Windows)
        key = os.urandom(length)
    elif platform.system() in ['Linux', 'Darwin']:
    # Use /dev/random for Unix-based systems
        with open('/dev/random', 'rb') as random_source:
            key = random_source.read(length)
    else:
        raise NotImplementedError("This platform is not supported.")
    return key

length = 16
# count of bytes for key
key = generate_key_with_dev_random(length)
print("Key (hex):", key.hex())