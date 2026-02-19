"""Template subpackage exports.

This file corrects a previous misnaming ('__init__ .py' with a space) that
prevented Python from recognizing the directory as a proper package.
"""

from . import renderers

__all__ = ["renderers"]
