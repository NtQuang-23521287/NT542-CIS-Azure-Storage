import logging
import os

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename="logs/compliance_monitor.log",
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def log_event(message: str):
    logging.info(message)