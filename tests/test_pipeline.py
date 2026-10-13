import random
import threading
import time
import unittest

from nsz import Pipeline


class OrderedMapTest(unittest.TestCase):
    def test_preserves_input_order(self):
        def slowDouble(x):
            time.sleep(random.random() / 500)
            return x * 2

        results = list(Pipeline.orderedMap(slowDouble, range(500), 8, 16))
        self.assertEqual(results, [x * 2 for x in range(500)])

    def test_worker_exception_propagates(self):
        def failOn37(x):
            if x == 37:
                raise ValueError("boom")
            return x

        with self.assertRaises(ValueError):
            list(Pipeline.orderedMap(failOn37, range(100), 4, 8))

    def test_producer_exception_propagates(self):
        def items():
            yield 1
            yield 2
            raise IOError("read failed")

        with self.assertRaises(IOError):
            list(Pipeline.orderedMap(lambda x: x, items(), 2, 2))

    def test_early_exit_stops_feeder_and_threads(self):
        threadsBefore = threading.active_count()
        produced = []

        def items():
            for i in range(100000):
                produced.append(i)
                yield i

        results = Pipeline.orderedMap(lambda x: x, items(), 2, 4)
        for result in results:
            if result == 10:
                break
        results.close()
        self.assertLess(len(produced), 100)
        self.assertEqual(threading.active_count(), threadsBefore)


if __name__ == "__main__":
    unittest.main()
