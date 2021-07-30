# to run the test requires install redis-py library through pip,
# sudo pip3 install redis
import sys
from redis import Redis

TIMEOUT_SEC = 15
ITERATION_NUM = 10000

host, port = (sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else ("localhost", "6379")


redis_host = "localhost"
r = Redis(host=redis_host, port=port, socket_connect_timeout=TIMEOUT_SEC)

# heartbeat check
r.ping()
print(f"\n>>>>>>>>>>>>>>Connected to redis server {host}:{port}")

# test set/get function
key = "key"
for i in range(ITERATION_NUM):
    value = f"value-{i}"
    r.set(key, value)
    result = r.get(key)
    assert result.decode("utf-8") == value

# test set/get/delete function
for i in range(ITERATION_NUM):
    key, value = f"foo-{i}", f"bar-{i}"
    r.set(key, value)
    assert r.get(key).decode("utf-8") == value
    r.delete(key)
    assert r.get(key) is None

print("all tests passed")
