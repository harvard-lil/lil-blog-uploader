"""Handles all exceptions (including HTTPExceptions like 404) thrown during execution.

   Serves the user an appropriate error page, and if appropriate,
   logs the error (which notifies application admins)."""
# Adapted from https://realpython.com/blog/python/python-web-applications-with-flask-part-iii/
from flask import current_app, Markup, render_template, request
from werkzeug.exceptions import default_exceptions, HTTPException

def error_handler(error):
    """Handler for all exceptions"""
    if isinstance(error, HTTPException):
        description = error.get_description(request.environ)
        code = error.get_response().status_code
        name = error.name
    else:
        description = ("We encountered an error while trying to fulfill your request")
        code = 500
        name = 'Internal Server Error'

    if code not in [400, 401, 403, 404, 405]:
        msg = "Request resulted in {}".format(name)
        current_app.logger.error(msg, exc_info=error)

    heading = name + " (" + unicode(code) + ")"
    message = description

    templates_to_try = ['{}.html'.format(code), 'generic.html']
    return render_template(templates_to_try, context={'heading': heading, 'message': message}), code


def init_app(app):
    """Registers all handlers, in order"""
    with app.app_context():
        if not current_app.debug:
            for exception in default_exceptions:
                app.register_error_handler(exception, error_handler)
            app.register_error_handler(Exception, error_handler)
