"""test module for all tests related code

The module includes all pipeline related tests implementations and interfaces.
"""

import argparse as ap
from typing import Dict, List, Tuple, Set
from abc import ABCMeta, abstractmethod
from utils import *
from logger import Logger

parser = ap.ArgumentParser(description="Arguments for testing.")
parser.add_argument("-m",
                    "--mode",
                    dest="mode",
                    choices=["terminal", "pipeline"],
                    default="pipeline",
                    help="mode to run the tests [terminal, pipeline]")
parser.add_argument("-ut",
                    "--unit-tests",
                    dest="unittests",
                    nargs='*',
                    default=[],
                    help="the unit tests to run, empty to run all")

parser.add_argument("-ct",
                    "--libc-tests",
                    dest="libctests",
                    nargs='*',
                    default=[],
                    help="the libc tests to run, empty to run all")

args = parser.parse_args()


def main():
    mode = args.mode
    if mode == "pipeline":
        if args.libctests and run_libc_tests():
            raise LibCTestError()
        elif not args.libctests and config.UNIT_TEST_ON and run_unit_tests():
            raise UnitTestError()
    # TODO: add sample, libc and other tests
    else:  # terminal mode, will override some configurations in config.py file
        unit_tests = args.unittests
        if unit_tests is not None:
            if len(unit_tests) > 0:
                # having specified test(s), run INCLUDE Mode
                config.UNIT_TEST_INCLUDE = {t: None for t in unit_tests}
                config.UNIT_TEST_MODE = config.TestMode.INCLUDE
            else:
                # just run exclude mode, the tests in config.EXCLUDE list will
                # still be evaluated
                config.UNIT_TEST_MODE = config.TestMode.EXCLUDE
            run_unit_tests()


class TestError(RuntimeError):
    """Parent class for all test errors.

    """
    pass


class UnitTestError(TestError):
    pass


class LibCTestError(TestError):
    pass


class AbstractTest(metaclass=ABCMeta):
    """Abstrct class for all test types

    All class type should inheritate the Abstract Test class and implement there
    own run test strategy. There are 3 default testing steps with implementation, 
    overwrite the command or implementation if needed:
    - clean_up: being used to clean up all existing artifacts 
    - build: being used to build the artifacts/executable
    - run: run the built artifacts/executable
    """
    def __init__(self, name: str, path: str):
        """
        constructor function. 

        """
        self.path, self.name, self.success = path, name, False
        self.target_suffix = f"-C {path}"
        self.logger = Logger.Instance()
        super().__init__()

    def clean_up(self, command: str = "make clean", args: str = None) -> str:
        out, err = exec_shell_command(f"{command} {args if args else ''}")
        self.logger.log_test_step(out, err, "clean_up", self.name, self.path)
        return err

    def build(self, command: str = "make", args: str = None) -> str:
        out, err = exec_shell_command(f"{command} {args if args else ''}")
        self.logger.log_test_step(out, err, "build", self.name, self.path)
        return err

    def run(self, command: str = "make tests", args: str = None) -> str:
        out, err = exec_shell_command(f"{command} {args if args else ''}")
        self.logger.log_test_step(out, err, "run", self.name, self.path)
        return err

    @abstractmethod
    def run_test(self):
        pass


class UnitTest(AbstractTest):
    """Concrete implementation for Unit Tests

    The class using all default implementations and having a run test order:
    clean_up -> build -> run
    """
    def verify(self):
        # TODO: verify the test is valid, e.g. having correct directory structure and Makefile
        pass

    def run_test(self):
        if self.clean_up(args=self.target_suffix): return
        if self.build(args=self.target_suffix): return
        if self.run(args=self.target_suffix): return
        self.success = True


class LibCTest(AbstractTest):
    """Concrete implementation for LibC Tests

    The class using all default implementations and having a run test order:
    clean_up -> build -> run
    """

    def __init__(self, name: str, path: str):
        """
        constructor function.

        """
        super().__init__(name, path)
        self.target_suffix = f"-C {config.LIBC_TEST_ROOT}"

    def run_test(self):
        if self.run(command="make run", args=f"{self.target_suffix} TEST={self.path}"): return
        self.success = True


def run_unit_tests() -> List[UnitTest]:
    """ run the unit tests and get result summary 

    run all unit tests based on rules configured in configuration file. All test results 
    will be logged. At the end there will be summary for failed/success/excluded/run tests.
    """
    candidates, selected_tests = get_test_candidates(UnitTest)
    records = []
    # TODO: optimize for parallel execution
    failures = []
    for name, path in candidates.items():
        records.append(f"{name}\t:{path}")
        unit_test = UnitTest(name, path)
        unit_test.run_test()
        if not unit_test.success:
            failures.append(unit_test)

    message = []
    message.append("Unit Tests Running Summary:")
    message.append(f"Testing Mode - {config.UNIT_TEST_MODE.name}")
    message.append(
        f"Success/Fail: {len(candidates)-len(failures)}/{len(failures)} out of {len(candidates)} Tests."
    )
    message.append("\nList of Unit Tests Run:\n{}".format("\n".join(
        sorted(records))))
    if failures:
        message.append("\nList of Failed Unit Tests:\n{}".format("\n".join([
            f"{ut.name}\t:{ut.path}"
            for ut in sorted(failures, key=lambda t: t.name)
        ])))
    if config.TestMode.EXCLUDE == config.UNIT_TEST_MODE and selected_tests:
        message.append("\nList of Excluded Unit Tests:\n{}".format("\n".join(
            [f"\t{p}" for p in sorted(selected_tests)])))

    logger = Logger.Instance()
    logger.log_test_summary('\n'.join(message))

    return failures


def get_test_candidates(
        _class: AbstractTest) -> Tuple[Dict[str, str], Set[str]]:
    """get all candidates and selected_tests(include/exclude) for test running.

    try to parse the run test rules in config file. Filter out the candidates for test running and 
    selected_tests for include/exclude.
    """
    if _class == UnitTest:
        test_category = config.UNIT_TEST_MODE
        include_tests = config.UNIT_TEST_INCLUDE
        exclude_tests = config.UNIT_TEST_EXCLUDE
        tests_directory = config.UNIT_TEST_SRC_ROOT

    selected_test_paths = set()
    selected_tests: dict = include_tests if test_category == config.TestMode.INCLUDE else exclude_tests

    for name, path in selected_tests.items():
        test_path = parse_test_path(name, path, _class)
        selected_test_paths.add(test_path)

    candidates: dict = {}
    for test in list_dir(tests_directory):
        path = parse_test_path(test, None, _class)
        if not path: continue

        qualify = test_category == config.TestMode.EXCLUDE and path not in selected_test_paths \
            or test_category == config.TestMode.INCLUDE and path in selected_test_paths
        if qualify:
            candidates[test] = path

    return candidates, selected_test_paths


def run_libc_tests() -> List[LibCTest]:
    """ run the libc tests and get result summary 

    run all unit tests based on rules configured in configuration file. All test results 
    will be logged. At the end there will be summary for failed/success/excluded/run tests.
    """
    candidates, selected_tests = get_libc_test_candidates()
    records = []
    # TODO: optimize for parallel execution
    failures = []
    for name, path in candidates.items():
        records.append(f"{name}\t:{path}")
        libc_test = LibCTest(name, path)
        libc_test.run_test()
        if not libc_test.success:
            failures.append(libc_test)

    message = []
    message.append("LibC Tests Running Summary:")
    message.append(f"Testing Mode - INCLUDE")
    message.append(
        f"Success/Fail: {len(candidates)-len(failures)}/{len(failures)} out of {len(candidates)} Tests."
    )
    message.append("\nList of LibC Tests Run:\n{}".format("\n".join(
        sorted(records))))
    if failures:
        message.append("\nList of Failed LibC Tests:\n{}".format("\n".join([
            f"{ut.name}\t:{ut.path}"
            for ut in sorted(failures, key=lambda t: t.name)
        ])))

    logger = Logger.Instance()
    logger.log_test_summary('\n'.join(message))

    return failures


def get_libc_test_candidates() -> Tuple[Dict[str, str], Set[str]]:
    """get all libc candidates and selected_tests(include) for test running.
    
    """
    
    selected_test_paths = set()
    selected_tests: dict = config.LIBC_TEST_INCLUDE

    for name, path in selected_tests.items():
        selected_test_paths.add(path)

    return selected_tests, selected_test_paths


def parse_test_path(name: str, path: str, _class: AbstractTest) -> str:
    """ parse the test absolute path

    Based on given path name and/or path, do a fuzzy guess and parse it 
    to absolute path. The parsing rule is as following
    - if absolute path provided and is valid, will use absolute path
    - if path with tests root folder provided and is valid, will use the path
    - if path with only test directory is provided, will guess and verify if the TEST_SRC_ROOT/test_path is valide
    - if no valid provided path, will try to use test_name to infere test path as TEST_SRC_ROOT/test_name
    - so all following name:path formats are valid and can be parsed
        - "conf": "tests/conf",
        - "conf": "conf",
        - "conf": None,   
    """
    # fuzzy matching to get test directory real path
    if _class == UnitTest:
        tests_directory = config.UNIT_TEST_SRC_ROOT
    if path:
        # check absolute path
        if exists_dir(generate_abs_path(path)):
            return generate_abs_path(path)
        # check path with Project root, PRJ_ROOT/path
        elif exists_dir(generate_abs_path(config.PRJ_ROOT, path)):
            return generate_abs_path(config.PRJ_ROOT, path)
        # check path with Test root, TEST_SRC_ROOT/path
        elif exists_dir(generate_abs_path(tests_directory, path)):
            return generate_abs_path(tests_directory, path)

    # check with test name if all path matching method not working
    # TEST_SRC_ROOT/name
    abs_path = generate_abs_path(tests_directory, name)

    return abs_path if exists_dir(abs_path) else None


if __name__ == "__main__":
    main()
