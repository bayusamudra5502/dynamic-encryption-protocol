class LogLevel:
    DEBUG = (0, "DEBUG")
    INFO = (1, "INFO")
    WARNING = (2, "WARNING")
    ERROR = (3, "ERROR")


class Log:
    LEVEL = LogLevel.DEBUG

    @staticmethod
    def log(level, msg):
        if Log.LEVEL[0] <= level[0]:
            print("[DEBUG]", msg)

    @staticmethod
    def debug(msg, *, service=None):
        if service == None:
            Log.log(LogLevel.DEBUG, msg)
        else:
            Log.log(LogLevel.DEBUG, f"(Service: {service})" + msg)

    @staticmethod
    def info(msg, *, service=None):
        if service == None:
            Log.log(LogLevel.INFO, msg)
        else:
            Log.log(LogLevel.INFO, f"(Service: {service})" + msg)

    @staticmethod
    def warn(msg, *, service=None):
        if service == None:
            Log.log(LogLevel.WARNING, msg)
        else:
            Log.log(LogLevel.WARNING, f"(Service: {service})" + msg)

    @staticmethod
    def error(msg, *, service=None):
        if service == None:
            Log.log(LogLevel.ERROR, msg)
        else:
            Log.log(LogLevel.ERROR, f"(Service: {service})" + msg)
