import logging

logging.basicConfig(filename='applicationlog.log', level=logging.INFO)

class Logger:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.log = self.logger.log
        self.info = self.logger.info
        self.warning = self.logger.warning
        self.error = self.logger.error
        self.critical = self.logger.critical
        self.exception = self.logger.exception
        self.disable = self.logger.disable

    