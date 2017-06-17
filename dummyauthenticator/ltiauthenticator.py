from traitlets import Unicode
from jupyterhub.handlers import BaseHandler

from jupyterhub.auth import Authenticator
import logging
from tornado import gen, web, httputil
from lti import ToolProvider
from oauthlib.oauth1 import RequestValidator
from jupyterhub.utils import url_path_join
import collections

logger = logging.getLogger('LTIAuth')

class TornadoToolProvider(ToolProvider):
    # @classmethod
    # def decode(cls, data):
    #     if isinstance(data, bytes):
    #         return data.decode()
    #     elif isinstance(data, collections.Mapping):
    #         return dict(map(cls.decode, data.items()))
    #     elif isinstance(data, collections.Iterable):
    #         return type(data)(map(cls.decode, data))
    #     else:
    #         return data

    @classmethod
    def from_tornado_request(cls, secret=None, request=None):
        if request is None:
            raise ValueError('request must be supplied')

        headers = request.headers
        url = request.uri
        # params = {}
        # content_type = request.headers.get('content-type')
        # logger.warn("content-type: " + content_type)
        # httputil.parse_body_arguments(content_type, request.body, params, None)
        params = dict(request.body_arguments)
        # params_decoded = cls.decode(params)
        params_decoded = {}
        for key, val in params.items():
            if isinstance(val, list):
                val_decoded = ','.join(map(lambda x: x.decode().strip(), val))
            else:
                val_decoded = val.decode()
            params_decoded[key] = val_decoded
        logger.warn(params_decoded)

        return cls.from_unpacked_request(secret, params_decoded, url, headers)


class LTILoginHandler(BaseHandler):

    def get(self):
        raise web.HTTPError(401)

    def post(self):
        secret = self.authenticator.secret or "SECRET"
        tool_provider = TornadoToolProvider.from_tornado_request(secret, self.request)

        # validator = RequestValidator()
        fullname = self.request.arguments['lis_person_name_full']
        username = 'anaderi' # TODO

        # ok = tool_provider.is_valid_request(validator)
        ok = True
        logger.info("ok = %s" % ok)

        if not ok:
            raise web.HTTPError(401)
        else:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))


class LTIAuthenticator(Authenticator):
    secret = Unicode(
        None,
        allow_none=True,
        config=True,
        help="""
        secret
        """
    )

    def get_handlers(self, app):
        return [
            (r'/login', LTILoginHandler),
        ]    

    @gen.coroutine
    def authenticate(self, handler, data):
        logger = logging.getLogger()
        logging.info("LTI authenticate")
        logging.info(data)
        
        return data['username']

        # if self.password:
        #     if data['password'] == self.password:
        #         return data['username']
        #     return None
        # return data['username']
