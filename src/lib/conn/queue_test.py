from lib.conn.QueueSocket import QueueSocketTransport


def test_queue_socket():
    q = QueueSocketTransport()
    q.send(b"Hello, World!")
    assert q.recv(5) == b"Hello"
    assert q.recv(8) == b", World!"
