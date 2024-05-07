from lib.data.finish import Finished


def test_finished():
    fin = Finished(b"finished")

    finished_encoded = fin.encode()
    finished_new = Finished.parse(finished_encoded)

    assert fin == finished_new
    assert fin.length() == 8
