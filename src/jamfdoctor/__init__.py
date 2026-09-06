"""jamfdoctor: local, deterministic, evidence-first diagnostics for Jamf Pro.

It reads text you already have (a policy log pasted from Jamf Pro, or a policy
exported as JSON), matches a fixed rule catalog, and reports each finding with
the exact lines it matched and the next read-only check to run. It never talks
to a Jamf Pro server.
"""

__version__ = "0.1.0"
