"""
Точка входа для запуска Sentinel SIEM SOC Platform.
"""

from sentinel.ui.app import SentinelSIEMApp

if __name__ == "__main__":
    app = SentinelSIEMApp()
    app.mainloop()

