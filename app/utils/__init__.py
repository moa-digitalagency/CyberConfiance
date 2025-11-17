import logging
from datetime import datetime

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def format_datetime(dt):
    if isinstance(dt, datetime):
        return dt.strftime('%d/%m/%Y %H:%M')
    return ''
