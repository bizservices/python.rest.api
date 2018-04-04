import xmltodict
import yaml
import uuid
import time
from urllib.parse import urlparse

from flask import Flask, request, jsonify, make_response, send_file, g
from flask.views import View, MethodView
from flask_cors import CORS
from werkzeug.routing import BaseConverter

from yourapi.rest.framework.content.json import JSONEncoder
import yourapi.rest.framework.content.json as json
from yourapi.rest.framework.content.xml import convert_to_xml
from yourapi.rest.framework.content.yaml import convert_to_yaml
from yourapi.rest.framework.core import Application
from yourapi.rest.framework.utils import UriIdentifier
from yourapi.rest.providers.flask.exceptions import FlaskException, flask_raise
from yourapi.rest.framework.call_proxy import default_url_root
from yourapi.rest.framework.logging import getLogger, change_log_level, WARNING, CRITICAL  # This will also init logging
from yourapi.basic.types import c, cdict
from yourapi.config import CONTAINER, TRACE_PERFORMANCE, DEBUG
from yourapi.rest.framework.tracing import trace_publisher

# default request content type
DEFAULT_REQUEST_CONTENT_TYPE = 'text/yaml'
# response content types
SUPPORTED_RESPONSE_CONTENT_TYPES = ('json', 'xml', 'yaml')
DEFAULT_RESPONSE_CONTENT_TYPE = 'json'

# Get the logger for this module
flask_logger = getLogger(__name__)
# silence certain loggers
change_log_level(['gunicorn', 'werkzeug'], lvl=WARNING)
change_log_level(['pika'], lvl=CRITICAL)


class RequestHandler(object):
    """The requesthandler enables translating specific Flask exceptions to general framework exceptions.
    Also headers are added for future processing and transparent authentication flow.
    This object can be integrated with the yourapi object in the future.
    """
    def __init__(self, application: Application):
        # Get the framework-application from the handler and store it for future use:
        self.application = application

    def headers(self, arguments={}):
        """Return a dictionary with all headers in the request."""
        # TODO: from this point on, the headers dict should be case insensitive
        # flask_logger.debug("Request headers: {}".format(request.headers))
        headers = cdict({k:v for k,v in request.headers.items() if k.lower() in
                         ['x-auth-scopes', 'authorization', 'x-trace-seq-next', 'x-trace-depth', 'x-trace-uuid']})
        token_keys = [k for k in arguments.keys() if k.lower() == 'authorization']
        if not headers.get('authorization'):
            # No authorzation header present, get it from arguments or cookies:
            if token_keys:
                token_key = token_keys[0]
                headers['Authorization'] = arguments[token_key]
                del arguments[token_key]
            elif request.cookies.get('token'):
                headers['Authorization'] = 'Bearer ' + request.cookies.get('token')
        return dict(headers)   # Headers is assumed to be a dict type elsewhere, have to refactor cdict...

    @flask_raise
    def get(self, subdomain, version, project, domain, resource, id, deep_uri, arguments, url_root):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=resource)
        # Now inspect the plugin and see which methods must be called with which arguments:
        # The querystring arguments are used for get method. The arguments have multuiple values in a list;
        # retrieve last element as this is specified as used argument in requesthandler.get_argument()
        return self.application.get(uri_id, id, deep_uri, self.headers(arguments), arguments, url_root)

    @flask_raise
    def post(self, subdomain, version, project, domain, resource, id, deep_uri, data, url_root=None, premade_uiid=None):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=resource)
        # The content for the post method is supplied in the body. The (json-)content is decoded and placed in the
        # (non-standard) body_content parameter.
        if premade_uiid:
            premade_uiid = uuid.UUID(premade_uiid)
        return self.application.post(uri_id, id, deep_uri, self.headers(), data, premade_uuid=premade_uiid, url_root=url_root)

    @flask_raise
    def put(self, subdomain, version, project, domain, resource, id, deep_uri, data, url_root):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=resource)
        # The content for the put method is supplied in the body. The (json-)content is decoded and placed in the
        # (non-standard) body_content parameter.
        return self.application.put(uri_id, id, deep_uri, self.headers(), data, url_root)

    @flask_raise
    def patch(self, subdomain, version, project, domain, resource, id, deep_uri, data, url_root):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=resource)
        # The content for the patch method is supplied in the body. The (json-)content is decoded and placed in the
        # (non-standard) body_content parameter.
        return self.application.patch(uri_id, id, deep_uri, self.headers(), data, url_root)

    @flask_raise
    def delete(self, subdomain, version, project, domain, resource, id, deep_uri, data, url_root):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=resource)
        # The content for the delete method is supplied in the body. The (json-)content is decoded and placed in the
        # (non-standard) body_content parameter.
        return self.application.delete(uri_id, id, deep_uri, self.headers(), data, url_root)

    def reload_plugin(self, subdomain, version, project, domain, plugin):
        uri_id = UriIdentifier(subdomain=subdomain, version=version, project=project, domain=domain, resource=plugin)
        return self.application.reload_plugin(uri_id)


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


framework_app = Application()
handler = RequestHandler(framework_app)
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.url_map.converters['regex'] = RegexConverter
app.json_encoder = JSONEncoder


# Update server name in config
flask_logger.info(f"Currently in container: {CONTAINER}")
server_name = urlparse(default_url_root).netloc
app.config.update(SERVER_NAME=server_name)
flask_logger.info("Set server name: {}".format(server_name))


class ViewHelpers(object):
    def get_arguments(self):
        """Get arguments and convert to a dictionary the framework can use

        The original code was based on the Tornado request object and no longer applies. The dictionary created
        here contains all key/value pairs as is, if there were multiple values for one key (as in ?foo=bar&foo=baz),
        the first is passed on, the rest ignored.

        TODO:
          - keys. Here, we want to convert all keys to our case insenitive python_varnames standard. Use our cdict.
          - multiple values for one key: ?foo=bar&foo=baz -- see issue #417
        """
        return {k: v for k, v in request.args.items()}

    def resource_content_type(self, resource):
        """Return type-suffixless resource and response content-type based on the resource

        :param resource: resource name as a string, possibly suffixed with response content type
                         Valid type suffixes include: SUPPORTED_RESPONSE_CONTENT_TYPES
                         Default response content type: DEFAULT_RESPONSE_CONTENT_TYPE
                         example: 'students' vs. 'students.xml'

        :returns resource, response content type
                resource: resource name as a string, suffix removed ('students') if there was a valid suffix
                response content type: one of SUPPORTED_RESPONSE_CONTENT_TYPES, default if no valid type suffix
        """
        r = resource.split('.')
        if len(r) > 1 and r[-1].lower() in SUPPORTED_RESPONSE_CONTENT_TYPES:
            # this resource has a valid suffix, separate them
            return '.'.join(r[:-1]), r[-1].lower()
        # this resource may have dots in it, but no valid suffix found
        return resource, DEFAULT_RESPONSE_CONTENT_TYPE

    def deep_uri_content_type(self, deep_uri):
        """Return content-type-less deep_uri and response content-type based on the deep_uri

        :param deep_uri: deep_uri as a string, possibly prefixed with response content type
                         Valid type prefixes include: SUPPORTED_RESPONSE_CONTENT_TYPES
                         Default response content type: DEFAULT_RESPONSE_CONTENT_TYPE
                         example: '/name' (education/students/{uuid}/name) vs. '.xml/name' (education/students/{uuid}.xml/name)

        :returns deep_uri, response content type
                deep_uri: deep_uri as a string, prefix removed if there was a valid prefix
                response content type: one of SUPPORTED_RESPONSE_CONTENT_TYPES, default if no valid type prefix
        """
        r = deep_uri.split('/')
        if len(r) > 1 and r[0].lower()[1:] in SUPPORTED_RESPONSE_CONTENT_TYPES:
            # we have a prefix and a deep_uri, separate them, don't forget to strip the leading dot from the prefix to
            # get to the content type
            return '/' + '/'.join(r[1:]), r[0][1:].lower()
        elif deep_uri[1:].lower() in SUPPORTED_RESPONSE_CONTENT_TYPES:
            # the deep_uri consists of just the content type
            return '', deep_uri[1:].lower()
        # there may have been a deep_uri, but there was no content type
        return deep_uri, DEFAULT_RESPONSE_CONTENT_TYPE

    def https_handling(self, request, base_url):
        """Make sure to pass on https if the original request, before forwarding, was https"""
        request_forwarded = request.headers.get("X-Forwarded-Proto")
        if request_forwarded and request_forwarded == "https":
            return base_url.replace("http", "https")
        else:
            return base_url

    def log_response(self, method, response, subdomain, project, domain, resource, uid=None):
        """Format how the response is logged"""
        # TODO: use logging Formatter instead to get more info logged (and add timestamp)
        flask_logger.info('{method} {response_status} - subdomain: "{subdomain}" {kind}: /{project}/{domain}/{resource}{uid}'.format(
            method=method,
            response_status=response.status,
            subdomain=subdomain,
            kind='item' if uid else'collection',
            project=project, domain=domain, resource=resource,
            uid='/{}'.format(uid) if uid else ''
        ))

    def convert_response(self, content, resource_name=None, type='json', status_code=None):
        """Convert the data to the specified type. Return a response with the correct headers."""

        def complete_response(response, cookies: list, *headerslist: dict):
            """Add the headers to the response and set a cookie if authorization header is set."""

            for headers in headerslist:
                for header_name, header_value in headers.items():
                    response.headers[header_name] = header_value
            # Now store cookie if provided:
            if cookies:
                for cookie in cookies:
                    response.set_cookie(**cookie)
            if status_code:
                response.status_code = status_code
            return response

        cookies = []
        # TODO: the response headers should originate from a cdict (or a Headers())
        headers = {}

        # response content can be a list or a dict
        if isinstance(content, dict):
            cookies = content.get('cookies', [])
            if content.get("_headers_") and isinstance(content.get("_headers_"), dict):
                # We need to filter out headers and add them to the response
                headers = content.get("_headers_")
                del content["_headers_"]
                # if isinstance(headers, dict) and not 'Access-Control-Allow-Origin' in headers.keys():
                #     headers['Access-Control-Allow-Origin'] = '*'
            if content.get('_file_download_'):
                # type is irrelevant, no decoding, just return content
                return send_file(content.get('_file_download_'), mimetype=headers.get('Content-Type'))

                # response = make_response(send_file(content.get('_file_download_')))
                # for header_name, header_value in headers.items():
                #     response.headers[header_name] = header_value
                # return response
            else:
                content = content.get("_body_", content)

        # now convert the content and update the headers appropriately according to type
        if type == 'json':
            response = jsonify(content)
            return complete_response(response, cookies, headers)
        elif type == 'xml':
            response = make_response(convert_to_xml(content, resource_name))
            return complete_response(response, cookies, headers, {'Content-Type': 'application/xml'})
        elif type == 'yaml':
            response = make_response(convert_to_yaml(content))
            return complete_response(response, cookies, headers, {'Content-Type': 'text/yaml; charset=utf-8'})
        else:
            return content

    def read_request(self, request):
        """Extract and convert the data from the request, according to the content type
        Supported: form, json, xml, yaml, and in a way, plain text/html

        Notes:
            - As soon as the request object is accessed (by for example request.data, request.header
        or request.host), the data (including form data) is cached. So it's probably a good idea to
        check content length first.
            - request.data wraps request.get_data(cache=True, as_text=False, parse_form_data=False)
        Consequence of this is that as soon as request.data is called, form data is parsed. If
        there is form data, request.data will come back and remain empty.
        """
        # TODO: check content length

        # get the content type from the request headers
        # TODO: what if client didn't provide content type - see issue #418
        request_content_type = request.headers.get('Content-Type', DEFAULT_REQUEST_CONTENT_TYPE).lower()

        # find the relevant data in the request and convert according to request content type
        if request.is_json and request.data:
            # Flask has got us covered, with application/json as well as application/*+json
            # and uses request.charset on json.loads if applicable.
            data = request.get_json()
        elif request.data:
            request_data = request.data.decode('utf-8')
            if request_content_type in ('application/xml', 'text/xml'):
                data = xmltodict.parse(request_data)
            elif request_content_type in ('application/yaml', 'text/yaml'):
                data = yaml.safe_load(request_data)
            else:
                # the content type is not one of the defaults we support
                # TODO: originally, we didn't support this case
                # TODO: pass on raw bytes string, or the utf-8 decoded version?
                # TODO: should we tell the user?
                data = request_data  # is allowed to be something other than a dict
        elif request.form:
            data = request.form_data_parser_class(request.form).stream_factory
            data = dict(data) if isinstance(data, dict) else {'form': data}
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}  # Flatten multi value by choosing the first element (arbitrarily)
        elif request.files:
            data = {}
            for file in request.files:
                # TODO: support uploading files in parts
                # TODO: support uploading multiple files in one request
                data = {"_file_upload_": request.files[file]}
                flask_logger.info('request.files detected, uploading \'{}\' ({}), ignoring any other files!'.format(
                    file, request.files[file].filename))
                break
        else:
            # if there was data in any form we support, we'd have caught it by now
            data = {}
        return data

    def fail_response(self, exc, resource, content_type, status_code=400):
        import traceback
        result = {"message": exc.args, "traceback": traceback.format_tb(exc.__traceback__)}
        response = self.convert_response(result, resource, content_type)
        response.status_code = status_code
        return response


class YourAPI(MethodView, ViewHelpers):
    def get(self, project, domain, resource, deep_uri, uid=None, subdomain=None):
        url_root = self.https_handling(request, request.url_root)
        if uid:
            # /domain/resource/{uuid}.xml - find content type based on deep_uri
            # TODO: this was originally called after getting result - failing into a not found
            deep_uri, response_content_type = self.deep_uri_content_type(deep_uri)
        else:
            # /domain/resource.xml - find content type based on resource
            resource, response_content_type = self.resource_content_type(resource)

        result = handler.get(subdomain, None, project, domain, resource, uid, deep_uri, self.get_arguments(), url_root)
        if hasattr(result, 'get') and result.get('_file_download_'):
            # type is irrelevant, no encoding, just return content.
            # TODO: if no mimetype, flask will try to guess based on filename - but there is no filename -- 500
            return send_file(result.get('_file_download_'), mimetype=result.get('_headers_', {}).get('Content-Type'))
        response = self.convert_response(result, resource, response_content_type)
        self.log_response('GET', response, subdomain, project, domain, resource, uid)
        return response

    def post(self, project, domain, resource, deep_uri, uid=None, premade_uuid=None, subdomain=None):
        deep_uri, response_content_type = self.deep_uri_content_type(deep_uri)
        try:
            data = self.read_request(request)
        except Exception as e:
            return self.fail_response(e, resource, response_content_type)

        url_root = self.https_handling(request, request.url_root)
        result = handler.post(subdomain, None, project, domain, resource, uid, deep_uri, data,
                              premade_uiid=premade_uuid, url_root=url_root)
        response = self.convert_response(result, resource, response_content_type, status_code=201)
        # TODO set correct Location headers, see issue #427
        if hasattr(result, 'get') and result.get('_href_'):
            response.headers['Location'] = result.get('_href_') # see also commit #fbd7989
        self.log_response('POST', response, subdomain, project, domain, resource, uid)
        return response

    def put(self, project, domain, resource, uid, deep_uri, subdomain=None):
        deep_uri, response_content_type = self.deep_uri_content_type(deep_uri)
        try:
            data = self.read_request(request)
        except Exception as e:
            return self.fail_response(e, resource, response_content_type)

        url_root = self.https_handling(request, request.url_root)
        result = handler.put(subdomain, None, project, domain, resource, uid, deep_uri, data, url_root)
        response = self.convert_response(result, resource, response_content_type, status_code=200)
        self.log_response('PUT', response, subdomain, project, domain, resource, uid)
        return response

    def patch(self, project, domain, resource, uid, deep_uri, subdomain=None):
        deep_uri, response_content_type = self.deep_uri_content_type(deep_uri)
        try:
            data = self.read_request(request)
        except Exception as e:
            return self.fail_response(e, resource, response_content_type)

        url_root = self.https_handling(request, request.url_root)
        result = handler.patch(subdomain, None, project, domain, resource, uid, deep_uri, data, url_root)
        response = self.convert_response(result, resource, response_content_type, status_code=200)
        self.log_response('PATCH', response, subdomain, project, domain, resource, uid)
        return response

    def delete(self, project, domain, resource, deep_uri, uid=None, subdomain=None):
        deep_uri, response_content_type = self.deep_uri_content_type(deep_uri)
        try:
            data = self.read_request(request)
        except Exception as e:
            return self.fail_response(e, resource, response_content_type)

        url_root = self.https_handling(request, request.url_root)
        result = handler.delete(subdomain, None, project, domain, resource, uid, deep_uri, data, url_root)
        response = self.convert_response(result, resource, response_content_type, status_code=204)
        self.log_response('DELETE', response, subdomain, project, domain, resource, uid)
        return response


class ResetPluginView(View, ViewHelpers):
    def dispatch_request(self, **kwargs):
        # TODO: full_dispatch_request() "Dispatches the request and on top of that performs request pre and
        # postprocessing as well as HTTP exception catching and error handling."
        result = handler.reload_plugin(kwargs.get('subdomain'), None, kwargs.get('project'), kwargs.get('domain'), kwargs.get('plugin'))
        resource, response_content_type = self.resource_content_type(kwargs.get('plugin'))
        response = self.convert_response(result, resource, response_content_type)
        self.log_response('RESET', response, kwargs.get('subdomain'), kwargs.get('project'), kwargs.get('domain'), resource)
        return response

yourapi_view = YourAPI.as_view('yourapi')
reset_plugin_view = ResetPluginView.as_view('reset_plugin')

app.add_url_rule('/<project>/<domain>/<resource>/<uuid:uid><regex("/?.*"):deep_uri>',
                 subdomain="<subdomain>",
                 view_func=yourapi_view,
                 methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])

app.add_url_rule('/<project>/<domain>/<resource><regex("/?.*"):deep_uri>',
                 subdomain="<subdomain>",
                 view_func=yourapi_view,
                 methods=['GET', 'POST', 'DELETE'])

app.add_url_rule('/<project>/<domain>/<resource>/premade_uuid=<regex("[-0-9a-f]*"):premade_uuid><regex("/?.*"):deep_uri>',
                 subdomain="<subdomain>",
                 view_func=yourapi_view,
                 methods=['POST',])

app.add_url_rule('/<project>/admin/refresh/<domain>/<plugin>',
                 subdomain="<subdomain>",
                 view_func=reset_plugin_view,
                 methods=['POST', ])


@app.after_request
def add_header(response):
    """Add cache and etag headers, default is private, 5 minutes"""
    if request.view_args and \
            c(request.view_args.get('subdomain', '')).like('cms(\.test|\.dev|.acc)?$') and \
            c(request.view_args.get('project', '')) == 'website' and \
            c(request.view_args.get('domain', '')) == 'content':
        # TODO: let tenant override the default cache settings
        # currently, we still need to implement cache control for our tenants
        # for the time being we hard-code the cms cache here
        response.cache_control.max_age = 3600
        response.cache_control.public = True
        response.vary.add('Origin')
    else:
        response.cache_control.max_age = 300
        response.cache_control.private = True
    # add etag for cache validation
    response.direct_passthrough = False  # file responses (cms images) failed to set an etag, this should fix it for now
    response.add_etag()

    return response


@app.before_request
def init_trace():
    """
    Records response time of a request. The 'g' (global) Flask object is used for the results.
    See http://flask.pocoo.org/docs/0.12/api/#flask.g

    :return:
    """
    if TRACE_PERFORMANCE:
        g.first_request = not any([k.lower() == 'x-trace-uuid' for k in request.headers.keys()])

        g.request_uuid = str(request.headers.get('x-trace-uuid', uuid.uuid4()))
        g.request_seq_this = int(request.headers.get('x-trace-seq-next', 0))
        g.request_seq_next = g.request_seq_this + 1
        g.request_depth = int(request.headers.get('x-trace-depth', -1)) + 1

        g.request_method = request.method
        g.request_url = request.url
        g.request_start = time.time()
        g.db_time = []


@app.after_request
def set_trace(response):
    """
    Set a header containing the request duration and push detailed trace to the MQ

    :param response:
    :return:
    """
    if TRACE_PERFORMANCE:
        req_time = int((time.time() - g.request_start) * 1000)

        trace = {
            "duration": req_time,
            "depth": g.request_depth,
            "method": g.request_method,
            "url": g.request_url,
            "uuid": g.request_uuid,
            "sequence": g.request_seq_this,
            "responseCode": response.status_code,
            "dbTime": g.db_time
        }
        if g.first_request:
            trace["totalRequestCount"] = g.request_seq_next

        trace_publisher.push('trace', trace)

        flask_logger.debug(f'request trace: {req_time} ms ({g.request_method} {g.request_url})')
        response.headers.add('x-trace-request-time', str(req_time))
        response.headers.add('x-trace-seq-next', str(g.request_seq_next))
    return response


def respond_on_error(error, add_traceback_to_response=False, add_traceback_to_log=False):
    """Create a response from the error, log the error/response and return the response

    TODO: can we move this to FlaskException.get_response(), as Werkzeug HTTPException.get_response()?
    TODO: prettier-print the traceback in the response based on the expected response content type - more readable in
          the browser
    """
    err_dict = error.to_dict()
    if not add_traceback_to_response and err_dict.get("traceback"):
        del err_dict["traceback"]
    response = jsonify(err_dict)
    response.status_code = error.status_code

    arguments = err_dict.get('arguments', str(error))
    log_str = '{method}{response_status} - message: "{message}"{arguments}'.format(
        method = '{} '.format(request.method) if request.method else '',
        response_status=response.status,
        message=str(err_dict.get('message', '')),
        arguments=' arguments: "{}"'.format(str(arguments)) if arguments else ''
    )
    if add_traceback_to_log:
        flask_logger.exception(log_str) # note that this logs on ERROR level
    else:
        flask_logger.info(log_str)

    return response


@app.errorhandler(FlaskException)
def handle_exception(error):
    """Place to handle all exceptions raised by framework or plugins

    For now, the only special case is 500: always add traceback to log, and also to response when on local

    TODO: add traceback to response on any dev-environment. I left this out because I'm not clear on what the urls
          for the different envs are going to look like
    TODO: the original page_not_found (404) function contained 2 checks: an 'if not error', in which case the error
          would be set to a default {"message": "No error message defined."}, and a try/except AttributeError around
          to_dict(), in which case the err_dict would be set to err_dict = {"message": e}. Why these checks?
          They seem redundant, correct me if I'm wrong, but I removed them.
    TODO: we could add headers here (or in get_error_response), for example for 405, response.headers = {bla}
    """
    if error.status_code == 500:
        add_traceback_to_log = True
        if 'local' in urlparse(request.base_url).netloc.split('.')[-1]:
            add_traceback_to_response = True
        else:
            add_traceback_to_response = False
        return respond_on_error(error, add_traceback_to_response=add_traceback_to_response,
                                add_traceback_to_log=add_traceback_to_log)
    return respond_on_error(error)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Development Server Help')
    parser.add_argument("-d", "--debug", action="store_true", dest="debug_mode",
                        help="run in debug mode (for use with PyCharm)", default=False)
    parser.add_argument("-p", "--port", dest="port",
                        help="port of server (default:%(default)s)", type=int, default=5000)
    parser.add_argument("-t", "--threaded", dest="threaded",
                        help="use multiple threads or not (default:%(default)s)", default=True)

    cmd_args = parser.parse_args()
    app_options = {"port": cmd_args.port, 'threaded': cmd_args.threaded}

    if cmd_args.debug_mode or DEBUG:
        flask_logger.warning('Running in debug mode')
        app_options["debug"] = True
        app_options["use_debugger"] = False
        app_options["use_reloader"] = False

    app.run(**app_options)
