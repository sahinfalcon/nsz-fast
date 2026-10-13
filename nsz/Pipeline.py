from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count
from queue import Empty, Queue
from threading import Event, Thread

_DONE = object()


class _Failure:
    def __init__(self, exception):
        self.exception = exception


def workerThreads(limit=None):
    threads = cpu_count() or 1
    if limit is not None:
        threads = min(threads, limit)
    return max(1, threads)


def orderedMap(fn, items, threads, window):
    """Yield fn(item) for every item, in input order.

    items is iterated on a feeder thread so producing work (sequential file reads, solid zstd
    decoding) overlaps with fn and with the consumer. fn runs on a thread pool. zstd, OpenSSL
    AES, hashlib and file I/O all release the GIL, so this scales without multiprocessing.
    At most window results are buffered ahead of the consumer.
    """
    queue = Queue(window)
    stop = Event()
    pool = ThreadPoolExecutor(threads)

    def feed():
        try:
            for item in items:
                if stop.is_set():
                    return
                queue.put(pool.submit(fn, item))
            queue.put(_DONE)
        except BaseException as e:
            queue.put(_Failure(e))

    feeder = Thread(target=feed, daemon=True)
    feeder.start()
    try:
        while True:
            entry = queue.get()
            if entry is _DONE:
                break
            if isinstance(entry, _Failure):
                raise entry.exception
            yield entry.result()
    finally:
        stop.set()
        # Unblock the feeder if it is waiting on a full queue, then let in-flight work finish
        while feeder.is_alive():
            try:
                queue.get_nowait()
            except Empty:
                feeder.join(0.01)
        pool.shutdown(wait=True)
