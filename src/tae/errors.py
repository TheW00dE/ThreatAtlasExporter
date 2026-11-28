"""Exceptions shared across packages."""


class InputError(Exception):
    """A file the user supplied (snapshot, rules, report definition, asset) is invalid."""


class EnvironmentProblem(Exception):
    """Something the tool needs from the machine is missing (e.g. PDF libraries)."""
