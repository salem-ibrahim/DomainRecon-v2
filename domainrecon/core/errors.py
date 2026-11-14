class DomainReconError(Exception):
    """Base exception for expected DomainRecon failures."""


class ScopeViolation(DomainReconError):
    """A value falls outside the authorized DNS scope or safety policy."""


class AuthorizationRequired(DomainReconError):
    """An active network action was requested without explicit approval."""


class ArtifactExists(DomainReconError):
    """An immutable scan artifact already exists."""
