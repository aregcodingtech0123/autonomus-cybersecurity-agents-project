"""Process exit codes shared by the CLI modules."""

EXIT_OK = 0
EXIT_ERROR = 1  # unexpected internal error (details in the log, traceback only with --debug)
EXIT_USAGE = 2  # bad arguments, refused native run, missing prerequisite, unknown id
EXIT_INTAKE = 3  # input rejected: intake limits, malformed or tampered audit data
EXIT_TOOLS = 4  # one or more tools failed or timed out
EXIT_ENV = 5  # Docker unreachable, images or rules missing
EXIT_CLEANUP = 6  # temporary files could not be removed
