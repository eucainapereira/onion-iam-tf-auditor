"""
Application adapter exposing lambda_handler from handler module.
Ensures full compatibility with both handler.lambda_handler and app.lambda_handler.
"""

from .handler import lambda_handler

__all__ = ["lambda_handler"]
