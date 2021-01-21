import sys
from pymemcache.client.base import Client

TIMEOUT_SEC = 15
NUM_TEST_PAIRS = 100
ip, port = (sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else ("localhost", "11211")

## Connect
print(f"connecting to {ip}:{port}")

try:
    client = Client((ip, port), connect_timeout=TIMEOUT_SEC, timeout=TIMEOUT_SEC)

    key, value = "some_key", "some_value"

    # cmd "set", create/update key:value
    assert client.set(key, value)

    # cmd "get", get value with key
    result = client.get(key).decode("utf-8")
    assert result == value

    # cmd "delete", delete key
    assert client.delete(key)

    # cmd "add", create key:value
    assert client.set(key, value)
    assert client.add(key, value)

    # cmd "append", append value
    res = client.append(key, "_suffix")
    value += "_suffix"
    assert client.get(key).decode("utf-8") == value

    # cmd "preppend", preppend value
    res = client.prepend(key, "prefix_")
    value = "prefix_" + value
    assert client.get(key).decode("utf-8") == value

    # cmd "replace", preppend value
    res = client.replace(key, "empty")
    assert client.get(key).decode("utf-8") == "empty"

    print("All tests passed!")

finally:
    client.close()
