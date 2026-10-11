import tempfile
import time
import unittest
from pathlib import Path
from database import MetricsDatabase
from monitor import LogMonitor


def line(path='/cat'):
    return f'198.51.100.77 - - [11/Oct/2026:12:00:00 +0000] "GET {path} HTTP/1.1" 200 42 "-" "test"\n'


class SecurityStub:
    def __init__(self):
        self.events = []

    def process_http(self, event, stats, enforce):
        self.events.append((event, stats, enforce))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'access.log'
        self.path.write_text('')
        self.db = MetricsDatabase(Path(self.temp.name) / 'metrics.db')
        self.security = SecurityStub()
        self.monitor = LogMonitor(self.path, self.db, self.security)

    def test_partial_line_and_restart(self):
        self.monitor.read_new_lines()
        raw = line()
        self.path.write_text(raw[:-1])
        self.monitor.read_new_lines()
        self.assertEqual(self.db.recent_events(), [])
        with self.path.open('a') as f:
            f.write('\n')
        self.monitor.read_new_lines()
        self.assertEqual(self.db.recent_events()[0]['path'], '/cat')
        self.assertTrue(self.security.events[-1][2])
        LogMonitor(self.path, self.db, self.security).read_new_lines()
        self.assertEqual(self.db.get_ip('198.51.100.77')['requests'], 1)

    def test_rotation_and_truncation(self):
        self.path.write_text(line('/long-original-path'))
        self.monitor.read_new_lines()
        self.path.write_text(line('/new'))
        self.monitor.read_new_lines()
        self.path.rename(self.path.with_suffix('.old'))
        self.path.write_text(line('/rotated'))
        self.monitor.read_new_lines()
        self.assertEqual(self.db.get_ip('198.51.100.77')['requests'], 3)
        self.assertEqual(self.db.recent_events()[0]['path'], '/rotated')

    def test_batches_keep_per_event_stats_and_checkpoint(self):
        self.path.write_text(line() * 1200)
        self.monitor.read_new_lines()
        self.assertEqual(len(self.security.events), 1200)
        self.assertEqual([s['requests'] for _, s, _ in self.security.events], list(range(1, 1201)))
        self.assertEqual(self.db.get_checkpoint(self.path)['offset'], self.path.stat().st_size)
        self.monitor.read_new_lines()
        self.assertEqual(self.db.get_ip('198.51.100.77')['requests'], 1200)

    def test_live_append_visible_within_one_second(self):
        self.monitor.read_new_lines()
        self.monitor.start()
        self.addCleanup(self.monitor.join, 2)
        self.addCleanup(self.monitor.stop)
        started = time.monotonic()
        with self.path.open('a') as f:
            f.write(line())
        while time.monotonic() - started < 1:
            if self.db.recent_events():
                break
            time.sleep(0.01)
        self.assertEqual(self.db.recent_events()[0]['path'], '/cat')
        self.assertLess(time.monotonic() - started, 1)


if __name__ == '__main__':
    unittest.main()
