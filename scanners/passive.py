#passive.py
"""
passive scanner passive.py from https://github.com/zaproxy/zap-api-python/blob/main/src/zapv2/pscan.py
Minimal Python wrapper for OWASP ZAP Passive Scan API.
Provides functions to monitor, enable, and control the passive scan queue.
"""
import six
import time


class PassiveScanner:
    """
    Minimal Python wrapper for OWASP ZAP Passive Scan API.
    Provides functions to monitor, enable, and control the passive scan queue.
    """

    def __init__(self, zap):
        self.zap = zap  # expects an initialized ZAPv2 client

    # ----- VIEW ENDPOINTS -----

    @property
    def records_to_scan(self):
        """Return the number of records remaining in the passive scan queue."""
        return int(six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/view/recordsToScan/')
        )))

    @property
    def scanners(self):
        """List passive scan rules with ID, name, enabled state, and threshold."""
        return six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/view/scanners/')
        ))

    # ----- ACTION ENDPOINTS -----

    def enable_all_scanners(self):
        """Enable all passive scan rules."""
        return six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/action/enableAllScanners/', {})
        ))

    def disable_all_scanners(self):
        """Disable all passive scan rules."""
        return six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/action/disableAllScanners/', {})
        ))

    def set_enabled(self, enabled=True):
        """Globally enable or disable passive scanning."""
        return six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/action/setEnabled/', {'enabled': str(enabled).lower()})
        ))

    def clear_queue(self):
        """Clear the passive scan queue."""
        return six.next(six.itervalues(
            self.zap._request(self.zap.base + 'pscan/action/clearQueue/', {})
        ))

    # ----- UTILITY -----

    def wait_until_done(self, poll_interval=2):
        """Wait until the passive scan queue is fully processed."""
        try:
            while True:
                remaining = self.records_to_scan
                print(f"\rPassive scan queue: {remaining}", end="", flush=True)
                if remaining == 0:
                    break
                time.sleep(poll_interval)
            print("\n[+] Passive scan complete.")
        except Exception as e:
            print(f"\n[~] Error checking passive queue: {e}")


# ----- WRAPPER FUNCTION -----

def run_passive(zap, poll_interval=2):
    """
    Run a full passive scan phase:
    - Enables all passive scanners
    - Waits for the passive scan queue to complete
    """
    print("\n[+] Starting Passive Scan phase...")
    try:
        pscan = PassiveScanner(zap)
        pscan.enable_all_scanners()
        pscan.set_enabled(True)
        pscan.wait_until_done(poll_interval=poll_interval)
        print("[+] Passive Scan phase complete.")
    except Exception as e:
        print(f"[~] Passive scan failed: {e}")