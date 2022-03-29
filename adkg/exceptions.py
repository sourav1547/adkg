class adkgError(Exception):
    """Base exception class."""


class ConfigurationError(adkgError):
    """Raise for configuration errors."""


class BroadcastError(adkgError):
    """Base class for broadcast errors."""


class RedundantMessageError(BroadcastError):
    """Raised when a rdundant message is received."""


class AbandonedNodeError(adkgError):
    """Raised when a node does not have enough peer to carry on a distirbuted task."""
