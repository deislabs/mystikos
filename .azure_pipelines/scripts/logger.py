import os, sys
scripts_root = sys.path[0]
sys.path.insert(1, os.path.join(scripts_root, '..'))
import config
import logging


class Logger():
    """Utility class used for logging
    
    Singleton logger utility class
    """
    __instance = None

    class __logger:
        def __init__(self):
            """concrete logger constructor

            initialization based on configurations in config.py file
            """
            logging.basicConfig(
                filename=config.LOG_FILE_PATH,
                level=config.LOG_LEVEL,
                format=
                f"[%(levelname)s]-[%(asctime)s]{'>'*config.LOG_SEPARATOR_LEN}\n%(message)s",
                datefmt='%m/%d/%y-%H:%M:%S,%a')

        def log_test_step(self,
                          stdout: str,
                          stderr: str = None,
                          step: str = None,
                          name: str = None,
                          path: str = None):
            """log test step 

            if standard error or standard output having content, will write to 
            related log levels based on configuration.
            """
            test_info = ""
            if name: test_info += f"Test: {name} "
            if path: test_info += f"Path: {path}"
            if test_info: test_info += "\n"
            if stdout:
                level = logging.ERROR if stderr else logging.DEBUG
                stdout_msg = f"{test_info}Step {step}: {stdout.decode('utf-8')}"
                self.log(message=stdout_msg, level=level)
                if config.LOG_PRINT_STDOUT_TO_TERMINAL or level == logging.ERROR:
                    print(stdout_msg)
            if stderr:
                stderr_msg = f"{test_info}Step {step}: {stderr.decode('utf-8')}"
                self.log(message=stderr_msg, level=logging.ERROR)
                if config.LOG_PRINT_STDERR_TO_TERMINAL:
                    print(stderr_msg)

        def log_test_summary(self, message):
            """log the summary

            """
            self.log(message=message, level=logging.CRITICAL)
            print(
                f"\n{'*'*config.LOG_SEPARATOR_LEN}\n{message}\n{'*'*config.LOG_SEPARATOR_LEN}\n"
            )

        def log(self, message: str, level=logging.INFO):
            logging.log(level=level, msg=message)

    @staticmethod
    def Instance():
        if not Logger.__instance:
            Logger.__instance = Logger.__logger()
        return Logger.__instance
