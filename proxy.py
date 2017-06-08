
def proxy_request(request, path):
    '''
        This function will be called on every web request caught by our
        default route handler (that is, on every request except for:
        a) requests for resources in /static and
        b) requests for urls with route especially defined in app.py.

        request = the request object as received by the parent Flask
        view function (http://flask.pocoo.org/docs/0.12/api/#incoming-request-data)

        path = the route requested by the user (e.g. '/path/to/route/i/want')

        proxy_response should return the response to be forwarded to the user.
        Treat it like a normal Flask view function:

        It should return a value that Flask can convert into a response using
        http://flask.pocoo.org/docs/0.12/api/#flask.Flask.make_response,
        just like any function you woulld normally decorate with @app.route('/route'),
        where Flask calls make_response implicitly.

        e.g.
        def proxy_request(request, path):
            return 'Hello World'

        You can use flask.make_response to help construct complex responses:
        http://flask.pocoo.org/docs/0.12/api/#flask.Flask.make_response
    '''
    pass
