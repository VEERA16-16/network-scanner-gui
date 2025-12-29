import threading
import psutil
import time
import logging

class SystemHealthMonitor:
    def __init__(self, cpu_threshold=75, mem_threshold=75, check_interval=2):
        """
        Monitors system CPU and memory usage periodically.
        Sets an 'overloaded' flag if thresholds are exceeded.
        Runs monitoring in a dedicated background thread.

        :param cpu_threshold: CPU usage % above which system considered overloaded.
        :param mem_threshold: Memory usage % above which system considered overloaded.
        :param check_interval: Seconds between health checks.
        """
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.check_interval = check_interval

        self.overloaded = False
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._monitor_loop)
        self._thread.daemon = True

    def start(self):
        if not self._thread.is_alive():
            self._thread.start()
            logging.info("SystemHealthMonitor started.")

    def stop(self):
        self._stop_event.set()
        self._thread.join()
        logging.info("SystemHealthMonitor stopped.")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                cpu_percent = psutil.cpu_percent(interval=1)  # blocks for 1 second
                mem_percent = psutil.virtual_memory().percent

                overloaded_now = cpu_percent >= self.cpu_threshold or mem_percent >= self.mem_threshold

                if overloaded_now and not self.overloaded:
                    logging.warning(f"System overloaded (CPU={cpu_percent}%, Mem={mem_percent}%)")
                elif not overloaded_now and self.overloaded:
                    logging.info(f"System normalized (CPU={cpu_percent}%, Mem={mem_percent}%)")

                self.overloaded = overloaded_now

            except Exception as e:
                logging.error(f"SystemHealthMonitor encountered an exception: {e}")

            # Sleep for check_interval minus the CPU measurement time (~1 sec)
            sleep_time = max(0, self.check_interval - 1)
            time.sleep(sleep_time)
